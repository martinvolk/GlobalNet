#include "gclient.h"

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

int _ssl_recv(Connection &self, char *data, size_t size){
	return BIO_read(self.in_read, data, size);
}

int _ssl_send(Connection &self, const char *data, size_t size){
	return BIO_write(self.in_write, data, size);
}

static int _ssl_connect(Connection &self, const char *host, uint16_t port){
	// since the connect call is meaningless for SSL node without an underlying socket
	// we forward it to the next node, but as a command. 
	if(self._output){
		stringstream ss;
		ss<<host<<":"<<port;
		self._output->sendCommand(*self._output, RELAY_CONNECT, ss.str().c_str(), ss.str().length());
		
		LOG("[ssl] sending relay connect to "<<self._output->host<<":"<<self._output->port);
		
		// we now set our own state to CONNECTING.
		// it will be changed to CONNECTED in the main loop once the 
		// output connection changes it's own state to connected. 
		self.state = CON_STATE_CONNECTING;
		return 1;
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
			CON_initSSL(*con, false);
			
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
	self.is_client = false;
	if(self._output)
		return self._output->listen(*self._output, host, port);
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
	if((self.state & CON_STATE_INITIALIZED) && (self._output->state & CON_STATE_CONNECTED)){
		// switch into handshake mode
		memcpy(self.host, self._output->host, ARRSIZE(self.host));
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
			self.close(self);
			return;
		}
		if(self.is_client == true){
			if((res = SSL_connect(self.ssl))>0){
				self.state = CON_STATE_ESTABLISHED;
				memcpy(self.host, self._output->host, ARRSIZE(self.host));
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
				memcpy(self.host, self._output->host, ARRSIZE(self.host));
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
				LOG(hexencode(tmp, rc));
			}
		}
		if((rc = SSL_read(self.ssl, tmp, SOCKET_BUF_SIZE))>0){
			//LOG("[SSL] recv: "<<self.host<<":"<<self.port<<" length: "<<rc<<" ");
			BIO_write(self.in_read, tmp, rc);
			
			LOG(hexencode(tmp, rc));
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
int CON_initSSL(Connection &self, bool client){
	CON_init(self, client);
	
	if(client)
		self.ctx = SSL_CTX_new (SSLv3_client_method ());
	else
		self.ctx = SSL_CTX_new (SSLv3_server_method ());

	/* if on the client: SSL_set_connect_state(con); */
	if(client){
		SSL_CTX_use_certificate_file(self.ctx,CLIENT_CERT, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(self.ctx,CLIENT_KEY, SSL_FILETYPE_PEM);
		if ( !SSL_CTX_check_private_key(self.ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    
    SSL_CTX_set_verify(self.ctx, SSL_VERIFY_NONE, 0);
		SSL_CTX_set_verify_depth(self.ctx,4);
	}
	else {
		SSL_CTX_use_certificate_file(self.ctx, SERVER_CERT, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(self.ctx, SERVER_KEY, SSL_FILETYPE_PEM);
		if ( !SSL_CTX_check_private_key(self.ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
		
		SSL_CTX_set_verify(self.ctx, SSL_VERIFY_NONE, 0);
		SSL_CTX_set_verify_depth(self.ctx,4);
	}
	
	self.ssl = SSL_new (self.ctx);
	
	/* bind them together */
	SSL_set_bio(self.ssl, self.read_buf, self.write_buf);
	
	self.type = NODE_SSL;
	
	self.state = CON_STATE_INITIALIZED;
	self.is_client = client;
	
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

