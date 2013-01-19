/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"

#define ERR_SSL(err) if ((err)<=0) { cout<<errorstring(err)<<endl; ERR_print_errors_fp(stderr); }


#define CLIENT_CERT "client.crt"
#define CLIENT_KEY "client.key"
#define SERVER_KEY "server.key"
#define SERVER_CERT "server.crt"

string hexencode(const char *data, size_t size){
	std::ostringstream os;
	os.fill('0');
	os<<std::hex;
	for(uint c=0; c<size;c++){
		unsigned char ch = data[c];
		if(ch > 'A' && ch < 'z')
			os<<ch;
		else
			os<<'.';
	}
	return os.str();
}
/*
void con_show_certs(Connection *c){   
	SSL* ssl = c->ssl;
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); 
	if ( cert != NULL )
	{
			printf("Server certificates:\n");
			line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
			printf("Subject: %s\n", line);
			free(line);       
			line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
			printf("Issuer: %s\n", line);
			free(line);       
			X509_free(cert);     
	}
	else
			printf("No certificates.\n");
}
*/

static void _init_ssl_ctx(SSL_CTX *ctx, const char* cert, const char *key){
	SSL_CTX_use_certificate_file(ctx,cert, SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx,key, SSL_FILETYPE_PEM);
	if ( !SSL_CTX_check_private_key(ctx) )
	{
			fprintf(stderr, "Private key does not match the public certificate\n");
			abort();
	}
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
	SSL_CTX_set_verify_depth(ctx,4);
}

static void _init_ssl_socket(Connection *sock, bool server_socket){
	if(server_socket){
		sock->ctx = SSL_CTX_new (SSLv3_server_method ());
		_init_ssl_ctx(sock->ctx, SERVER_CERT, SERVER_KEY);
		sock->ssl = SSL_new (sock->ctx);
		SSL_set_bio(sock->ssl, sock->read_buf, sock->write_buf);
	} else {
		sock->ctx = SSL_CTX_new (SSLv3_client_method ());
		_init_ssl_ctx(sock->ctx, CLIENT_CERT, CLIENT_KEY);
		sock->ssl = SSL_new (sock->ctx);
		SSL_set_bio(sock->ssl, sock->read_buf, sock->write_buf);
	}
	sock->server_socket = server_socket;
}

int _ssl_recv(Connection &self, char *data, size_t size){
	return BIO_read(self.in_read, data, size);
}

int _ssl_send(Connection &self, const char *data, size_t size){
	return BIO_write(self.in_write, data, size);
}

static int _ssl_connect(Connection &self, const char *host, uint16_t port){
	// since the connect call is meaningless for SSL node without an underlying socket
	// we forward it to the next node, but as a command. 
	if(!(self.state & CON_STATE_INITIALIZED)){
		ERROR("CAN ONLY USE CONNECT ON A NEWLY CREATED SOCKET!");
		return -1;
	}
	
	if(self._output){
		// initialize ssl client method 
		_init_ssl_socket(&self, false);
		
		if(self._output->type == NODE_PEER){
			LOG("[ssl] sending relay connect to "<<self._output->host<<":"<<self._output->port);
		
			stringstream ss;
			ss<<"udt:"<<host<<":"<<port;
			self._output->sendCommand(*self._output, RELAY_CONNECT, ss.str().c_str(), ss.str().length());
			return 1;
		}
		else {
			self._output->connect(*self._output, host, port);
			return 1;
		}
	}
	return -1;
}

Connection *_ssl_accept(Connection &self){
	// the accept call is meaningless to SSL node itself. 
	// but if there is a connection from downline then we gladly serve it. 
	if(self._output){
		Connection *peer = self._output->accept(*self._output);
		if(peer){
			Connection *con = NET_allocConnection(*self.net);
			CON_initSSL(*con);
			
			_init_ssl_socket(con, true);
			
			con->_output = peer;
			
			// the state now needs to be handshake because the connection 
			// is already assumed to be established. 
			// (now done in main loop)
			//con->state = CON_STATE_INITIALIZED;
			
			return con;
		}
	}
	return 0;
}

int _ssl_listen(Connection &self, const char *host, uint16_t port){
	if(!(self.state & CON_STATE_INITIALIZED)){
		ERROR("CAN ONLY USE LISTEN ON A NEWLY CREATED SOCKET!");
		return -1;
	}
	
	if(self._output){
		if(self._output->listen(*self._output, host, port)>0){
			_init_ssl_socket(&self, true);
			self.host = self._output->host;
			self.port = self._output->port;
			return 1;
		}
	}
	return -1;
}

void _ssl_run(Connection &self){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	if(!self._output){
		LOG("[warning] no backend set for the SSL connection!");
		return;
	}
	
	// if we are waiting for connection and the downline has changed it's state
	// to being connected, we can now switch to handshake mode and do the handshake. 
	if((self.state & CON_STATE_INITIALIZED) && self.ssl && self.ctx && (self._output->state & CON_STATE_CONNECTED)){
		// switch into handshake mode
		self.host = self._output->host;
		self.port = self._output->port;
		
		self.timer = milliseconds();
		self.state = CON_STATE_SSL_HANDSHAKE; 
	}
	if(self.state & CON_STATE_CONNECTED && self._output->state & CON_STATE_DISCONNECTED){
		self.state = CON_STATE_DISCONNECTED; 
	}
	
	// send / receive data between internal buffers and output 
	// but only if the connection is still valid. 
	if(!(self.state & CON_STATE_INVALID)){
		/// send/receive output data
		if(self._output ){
			self._output->run(*self._output);
			while(!BIO_eof(self.write_buf)){
				if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0)
					self._output->send(*self._output, tmp, rc);
			}
			if((rc = self._output->recv(*self._output, tmp, SOCKET_BUF_SIZE))>0){
				BIO_write(self.read_buf, tmp, rc);
			}
		}
	}
	
	// check if the async handshake is completed
	if(self.state & CON_STATE_SSL_HANDSHAKE){
		int res;
		
		// sometimes the underlying connection may fail or something else 
		// may happen that would make us forever stuck in handshake. 
		// we need to close if we stay here for too long.. 
		if((milliseconds()-self.timer) > CONNECTION_TIMEOUT){
			LOG("SSL: connection timed out!");
			self.close(self);
			return;
		}
		if(self.server_socket == false){
			if((res = SSL_connect(self.ssl))>0){
				self.state = CON_STATE_ESTABLISHED;
				self.host = self._output->host;
				self.port = self._output->port;
				LOG("ssl connection succeeded! Connected to peer "<<self.host<<":"<<self.port);
			}
			else{
				//ERR_SSL(res);
			}
		}
		else {
			if((res=SSL_accept(self.ssl))>0){
				self.state = CON_STATE_ESTABLISHED;
				self.host = self._output->host;
				self.port = self._output->port;
				LOG("ssl connection succeeded! Connected to peer "<<self.host<<":"<<self.port);
			}
			else{
				//ERR_SSL(res);
			}
		}
	} 
	
	// if the connection has been established then we can write our input data
	// to ssl and encode it. 
	if(self.state & CON_STATE_ESTABLISHED){
		if((rc = BIO_read(self.in_write, tmp, SOCKET_BUF_SIZE))>0){
			if((rc = SSL_write(self.ssl, tmp, rc))<=0){
				LOG("error sending ssl to "<<self.host<<":"<<self.port<<": "<<errorstring(SSL_get_error(self.ssl, rc)));
				ERR_SSL(rc);
			}
			
			if(rc>0){
				//LOG("[SSL] send: "<<self.host<<":"<<self.port<<" length: "<<rc<<" ");
				//LOG(hexencode(tmp, rc));
			}
		}
		if((rc = SSL_read(self.ssl, tmp, SOCKET_BUF_SIZE))>0){
			//LOG("[SSL] recv: "<<self.host<<":"<<self.port<<" length: "<<rc<<" ");
			BIO_write(self.in_read, tmp, rc);
			
			//LOG(hexencode(tmp, rc));
		}
	}
	
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(self._output && self._output->state & CON_STATE_DISCONNECTED){
		LOG("SSL: underlying connection lost. Disconnected!");
		self.state = CON_STATE_DISCONNECTED;
	}
}

static void _ssl_close(Connection &self){
	if(!self._output){
		self.state = CON_STATE_DISCONNECTED;
		return;
	}
	// send unsent data 
	while(!BIO_eof(self.in_write)){
		char tmp[SOCKET_BUF_SIZE];
		int rc = BIO_read(self.in_write, tmp, SOCKET_BUF_SIZE);
		int rs;
		if((rs = SSL_write(self.ssl, tmp, rc))>0){
			while(!BIO_eof(self.write_buf)){
				char tmp[SOCKET_BUF_SIZE];
				int rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE);
				self._output->send(*self._output, tmp, rc);
			}
		}
	}
	LOG("SSL: disconnected!");
	self._output->close(*self._output);
	self.state = CON_STATE_WAIT_CLOSE;
}
int CON_initSSL(Connection &self){
	CON_init(self);

	self.type = NODE_SSL;
	
	self.state = CON_STATE_INITIALIZED;
	
	self.connect = _ssl_connect;
	self.accept = _ssl_accept;
	self.send = _ssl_send;
	self.recv = _ssl_recv;
	self.run = _ssl_run;
	self.listen = _ssl_listen;
	self.close = _ssl_close;
	
	//self.on_data_received = _ssl_on_data_received;
	return 1;
}

