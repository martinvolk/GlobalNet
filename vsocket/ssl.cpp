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

void SSLNode::_init_ssl_socket(bool server_socket){
	SSLNode *sock = this;
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

void SSLNode::_close_ssl_socket(){
	if(this->ssl){
		SSL_shutdown(this->ssl);
		SSL_free(this->ssl);
		if(this->ctx)
			SSL_CTX_free(this->ctx);
		// restore bios because we are using them in other places and ssl retardedly frees them. 
		this->read_buf = BIO_new(BIO_s_mem());
		this->write_buf = BIO_new(BIO_s_mem());
		BIO_set_mem_eof_return(this->read_buf, -1);
		BIO_set_mem_eof_return(this->write_buf, -1);
	}
	this->ssl = 0;
	this->ctx = 0;
}

void SSLNode::do_handshake(SocketType type){
	if(type == SOCK_CLIENT){
		if(server_socket) _close_ssl_socket();
		if(!ssl) _init_ssl_socket(false);
	}
	else if(type == SOCK_SERVER){
		if(!server_socket) _close_ssl_socket();
		if(!ssl) _init_ssl_socket(true);
	}
	else{
		ERROR("SSL: UNSUPPORTED SOCKET TYPE!");
	}
	timer = milliseconds();
	state = CON_STATE_SSL_HANDSHAKE; 
}

int SSLNode::recv(char *data, size_t size, size_t minsize){
	if(BIO_ctrl_pending(this->in_read) < minsize) return 0;
	return BIO_read(this->in_read, data, size);
}

int SSLNode::send(const char *data, size_t size, size_t minsize){
	return BIO_write(this->in_write, data, size);
}

int SSLNode::connect(const URL &url){
	// since the connect call is meaningless for SSL node without an underlying socket
	// we forward it to the next node, but as a command. 
	if(!(this->state & CON_STATE_INITIALIZED)){
		ERROR("CAN ONLY USE CONNECT ON A NEWLY CREATED SOCKET!");
		return -1;
	}
	timer = milliseconds();
	if(this->_output){
		// initialize ssl client method 
		_init_ssl_socket(false);
		
		this->_output->connect(url);
		return 1;
	}
	return -1;
}

Node *SSLNode::accept(){
	// the accept call is meaningless to SSL node itthis-> 
	// but if there is a connection from downline then we gladly serve it. 
	if(this->_output){
		Node *peer = this->_output->accept();
		if(peer){
			SSLNode *con = new SSLNode(m_pNetwork);
			
			con->_init_ssl_socket(true);
			
			con->url = peer->url;
			
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

int SSLNode::listen(const URL &url){
	if(!(this->state & CON_STATE_INITIALIZED)){
		ERROR("CAN ONLY USE LISTEN ON A NEWLY CREATED SOCKET!");
		return -1;
	}
	
	if(this->_output){
		if(this->_output->listen(url)>0){
			_init_ssl_socket(true);
			this->url = this->_output->url;
			return 1;
		}
	}
	return -1;
}

void SSLNode::run(){
	char tmp[SOCKET_BUF_SIZE];
	int rc = 0;
	
	if(!this->_output){
		LOG("[warning] no backend set for the SSL connection!");
		return;
	}
	
	if(m_bProcessingMainLoop) return;
	SETFLAG(m_bProcessingMainLoop, 0);
	
	this->_output->run();
		
	// if we are waiting for connection and the downline has changed it's state
	// to being connected, we can now switch to handshake mode and do the handshake. 
	if((this->state & CON_STATE_INITIALIZED) && this->ssl && this->ctx && (this->_output->state & CON_STATE_CONNECTED)){
		// switch into handshake mode
		this->url = URL("ssl", this->_output->url.host(), this->_output->url.port());
		
		this->timer = milliseconds();
		this->state = CON_STATE_SSL_HANDSHAKE; 
		LOG("SSL: initializing handshake..");
	}
	if(this->state & CON_STATE_CONNECTED && this->_output->state & CON_STATE_DISCONNECTED){
		this->state = CON_STATE_DISCONNECTED; 
	}
	
	// send / receive data between internal buffers and output 
	// but only if the connection is still valid. 
	if(!(this->state & CON_STATE_INVALID)){
		/// send/receive output data
		if(this->_output ){
			this->_output->run();
			while(!BIO_eof(this->write_buf)){
				if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
					//LOG("SSL: "<<url.url()<<" sending "<<rc<<" bytes of encrypted data.");
					this->_output->send(tmp, rc);
				}
			}
			if((rc = this->_output->recv(tmp, SOCKET_BUF_SIZE))>0){
				//LOG("SSL: "<<url.url()<<" received "<<rc<<" bytes of encrypted data.");
				BIO_write(this->read_buf, tmp, rc);
			}
		}
	}
	
	// check if the async handshake is completed
	if(this->state & CON_STATE_SSL_HANDSHAKE){
		int res;
		
		// sometimes the underlying connection may fail or something else 
		// may happen that would make us forever stuck in handshake. 
		// we need to close if we stay here for too long.. 
		if((milliseconds()-this->timer) > CONNECTION_TIMEOUT){
			LOG("SSL: connection timed out! "<<url.url());
			state = CON_STATE_DISCONNECTED;
			//this->close();
			return;
		}
		if(this->server_socket == false){
			//LOG("SSL: Attempting to connect to "<<url.url());
			if((res = SSL_connect(this->ssl))>0){
				this->state = CON_STATE_ESTABLISHED;
				this->url = URL("ssl", this->_output->url.host(), this->_output->url.port());
				LOG("ssl connection succeeded! Connected to peer "<<url.url());
			}
			else{
				//ERR_SSL(res);
			}
		}
		else {
			//LOG("SSL: accepting ssl connections on "<<url.url());
			if((res=SSL_accept(this->ssl))>0){
				this->state = CON_STATE_ESTABLISHED;
				this->url = URL("ssl", this->_output->url.host(), this->_output->url.port());
				LOG("ssl connection succeeded! Connected to peer "<<url.url());
			}
			else{
				//ERR_SSL(res);
			}
		}
	} 
	
	// if the connection has been established then we can write our input data
	// to ssl and encode it. 
	if(this->state & CON_STATE_CONNECTED){
		if((rc = BIO_read(this->in_write, tmp, SOCKET_BUF_SIZE))>0){
			if((rc = SSL_write(this->ssl, tmp, rc))<=0){
				LOG("error sending ssl to "<<url.url()<<": "<<errorstring(SSL_get_error(this->ssl, rc)));
				ERR_SSL(rc);
			}
			
			if(rc>0){
				//LOG("[SSL] send: "<<url.url()<<" length: "<<rc<<" ");
				//LOG(hexencode(tmp, rc));
			}
		}
		if((rc = SSL_read(this->ssl, tmp, SOCKET_BUF_SIZE))>0){
			//LOG("[SSL] recv: "<<url.url()<<" length: "<<rc<<" ");
			BIO_write(this->in_read, tmp, rc);
			
			//LOG(hexencode(tmp, rc));
		}
	}
	
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(this->_output && this->_output->state & CON_STATE_DISCONNECTED){
		//LOG("SSL: underlying connection lost. Disconnected!");
		this->state = CON_STATE_DISCONNECTED;
	}
}

void SSLNode::close(){
	if(!this->_output){
		this->state = CON_STATE_DISCONNECTED;
		return;
	}
	// send unsent data 
	while(!BIO_eof(this->in_write)){
		char tmp[SOCKET_BUF_SIZE];
		int rc = BIO_read(this->in_write, tmp, SOCKET_BUF_SIZE);
		int rs;
		if((rs = SSL_write(this->ssl, tmp, rc))>0){
			while(!BIO_eof(this->write_buf)){
				char tmp[SOCKET_BUF_SIZE];
				int rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE);
				if(this->_output)
					this->_output->send(tmp, rc);
			}
		}
	}
	if(this->_output)
		this->_output->close();
	this->state = CON_STATE_WAIT_CLOSE;
	
	LOG("SSL: disconnected!");
}
SSLNode::SSLNode(Network *net):Node(net){
	this->state = CON_STATE_INITIALIZED;
	
	this->ssl = 0;
	this->ctx = 0;
	
	this->type = NODE_SSL;
}

SSLNode::SSLNode(Network *net, SocketType type):Node(net){
	this->state = CON_STATE_INITIALIZED;
	this->ssl = 0;
	this->ctx = 0;
	this->type = NODE_SSL;
	
	if(type == SOCK_SERVER){
		_init_ssl_socket(true);
		server_socket = true;
	}
	else if(type == SOCK_CLIENT){
		_init_ssl_socket(false);
		server_socket = false;
	}
}

SSLNode::~SSLNode(){
	if(!(this->state & CON_STATE_INVALID))
		this->close();
	
	_close_ssl_socket();
	
	LOG("SSL: deleted "<<url.url());
}
