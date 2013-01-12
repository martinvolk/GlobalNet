#include "gclient.h"

#define ERR_SSL(err) if ((err)<=0) { cout<<errorstring(err)<<endl; ERR_print_errors_fp(stderr); }


#define CLIENT_CERT "client.crt"
#define CLIENT_KEY "client.key"
#define SERVER_KEY "server.key"
#define SERVER_CERT "server.crt"

void con_show_certs(Connection *c){   
	SSL* ssl = c->ssl;
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	if ( cert != NULL )
	{
			printf("Server certificates:\n");
			line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
			printf("Subject: %s\n", line);
			free(line);       /* free the malloc'ed string */
			line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
			printf("Issuer: %s\n", line);
			free(line);       /* free the malloc'ed string */
			X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
			printf("No certificates.\n");
}

int _ssl_recv(Connection &self, char *data, size_t size){
	int rc; 
	if((rc = SSL_read(self.ssl, data, size))>0){
		LOG("[SSL] recv: "<<self.host<<":"<<self.port<<" length: "<<rc<<" ");
		
		std::ostringstream os;
		os.fill('0');
		os<<std::hex;
		for(int c=0; c<rc;c++){
			unsigned char ch = data[c];
			if(ch > 'A' && ch < 'z')
				os<<ch;
			else
				os<<'.';
		}
		
		LOG(os.str());
		return rc;
	}
	return -1;
}

int _ssl_send(Connection &self, const char *data, size_t size){
	int rc; 
	if((rc = SSL_write(self.ssl, data, size))<=0){
		LOG("error sending ssl to "<<self.host<<":"<<self.port<<": "<<errorstring(SSL_get_error(self.ssl, rc)));
		ERR_SSL(rc);
		return -1;
	}
	
	if(rc>0){
		LOG("[SSL] send: "<<self.host<<":"<<self.port<<" length: "<<rc<<" ");
		
		std::ostringstream os;
		os.fill('0');
		os<<std::hex;
		for(int c=0; c<rc;c++){
			unsigned char ch = data[c];
			if(ch > 'A' && ch < 'z')
				os<<ch;
			else
				os<<'.';
		}
		LOG(os.str());
	}
	return rc;
}

static int _ssl_connect(Connection &self, const char *host, uint16_t port){
	int ret = -1;
	if(self._next && (ret = self._next->connect(*self._next, host, port))>0){
		LOG("[ssl] connected to "<<host<<port);
		self.state = CON_STATE_SSL_HANDSHAKE;
	}
	return ret;
}

Connection *_ssl_accept(Connection &self){
	
	if(self._next){
		Connection *peer = self._next->accept(*self._next);
		if(peer){
			Connection *con = NET_allocConnection(*self.net);
			CON_initSSL(*con, false);
			con->_next = peer;
			con->state = CON_STATE_SSL_HANDSHAKE;
			return con; //require that underlying has a connection
		}
	}
	return 0;
}
int _ssl_listen(Connection &self, const char *host, uint16_t port){
	if(self._next)
		return self._next->listen(*self._next, host, port);
	return -1;
}

void _ssl_bridge(Connection &self, Connection *other){
	ERROR("[ssl] function bridge() not implemented!");
}
void _ssl_run(Connection &self){
	if(!self._next){
		LOG("[warning] no backend set for the SSL connection!");
		return;
	}
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	//LOG(self.write_buf->num_written);
	//LOG("[ssl] run "<<self.host<<":"<<self.port);
	
	// send/recv data
	if(self._next ){
		self._next->run(*self._next);
		while(!BIO_eof(self.write_buf)){
			if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0)
				self._next->send(*self._next, tmp, rc);
		}
		if((rc = self._next->recv(*self._next, tmp, SOCKET_BUF_SIZE))>0){
			BIO_write(self.read_buf, tmp, rc);
		}
	}
	
	// check if the async handshake is completed
	if(self.state == CON_STATE_SSL_HANDSHAKE){
		int res;
		if(self.is_client == true){
			if((res = SSL_connect(self.ssl))>0){
				self.state = CON_STATE_ESTABLISHED;
				LOG("ssl connection succeeded! Connected to peer "<<self.host<<":"<<self.port);
			}
			else{
				//ERR_SSL(res);
			}
		}
		else {
			if((res=SSL_accept(self.ssl))>0){
				self.state = CON_STATE_ESTABLISHED;
				LOG("ssl connection succeeded! Connected to peer "<<self.host<<":"<<self.port);
			}
			else{
				//ERR_SSL(res);
			}
		}
	}
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
	
	self.state = CON_STATE_SSL_HANDSHAKE;
	self.is_client = client;
	
	self.connect = _ssl_connect;
	self.accept = _ssl_accept;
	self.send = _ssl_send;
	self.recv = _ssl_recv;
	self.run = _ssl_run;
	self.listen = _ssl_listen;
	self.bridge = _ssl_bridge;
	//self.on_data_received = _ssl_on_data_received;
	return 1;
}

