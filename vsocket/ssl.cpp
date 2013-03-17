/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
	SSL* ssl = c->m_pSSL;
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
	this->read_buf = BIO_new(BIO_s_mem());
	this->write_buf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(this->read_buf, -1);
	BIO_set_mem_eof_return(this->write_buf, -1);
	
	if(server_socket){
		sock->m_pCTX = SSL_CTX_new (SSLv3_server_method ());
		_init_ssl_ctx(sock->m_pCTX, SERVER_CERT, SERVER_KEY);
		sock->m_pSSL = SSL_new (sock->m_pCTX);
		SSL_set_bio(sock->m_pSSL, sock->read_buf, sock->write_buf);
	} else {
		sock->m_pCTX = SSL_CTX_new (SSLv3_client_method ());
		_init_ssl_ctx(sock->m_pCTX, CLIENT_CERT, CLIENT_KEY);
		sock->m_pSSL = SSL_new (sock->m_pCTX);
		SSL_set_bio(sock->m_pSSL, sock->read_buf, sock->write_buf);
	}
	sock->server_socket = server_socket;
}

void SSLNode::_close_ssl_socket(){
	if(this->m_pSSL){
		SSL_shutdown(this->m_pSSL);
		SSL_free(this->m_pSSL);
		if(this->m_pCTX)
			SSL_CTX_free(this->m_pCTX);
	}
	this->read_buf = this->write_buf = 0;
	this->m_pSSL = 0;
	this->m_pCTX = 0;
}

void SSLNode::do_handshake(){
	timer = milliseconds();
	state = CON_STATE_SSL_HANDSHAKE; 
}

int SSLNode::recv(char *data, size_t size, size_t minsize) const{
	if(!(state & CON_STATE_CONNECTED)){
		LOG(3, "SSL: trying to receive from a socket that is not connected!");
		return 0;
	}
	//LOG(3, "SSL: read: pending: "<<m_DataBuffer.input_pending()<<" bytes.");
	int rc = m_DataBuffer.recv(data, size, minsize);
	if(rc>0) LOG(3, "SSL: recv "<<rc<<" bytes of data.");
	return rc;
}

int SSLNode::send(const char *data, size_t size){
	return m_DataBuffer.send(data, size);
}

int SSLNode::connect(const URL &url){
	// since the connect call is meaningless for SSL node without an underlying socket
	// we forward it to the next node, but as a command. 
	if(this->state & CON_STATE_CONNECTED || this->server_socket == true){
		ERROR("CAN ONLY USE CONNECT ON A NON CONNECTED CLIENT SOCKET!");
		return -1;
	}
	timer = milliseconds();
	
	// initialize ssl client method 
	_init_ssl_socket(false);
	m_pTransportLayer->connect(url);
	
	do_handshake();
	
	return 1;
}

int SSLNode::bind(const URL &url){
	// we don't have the concept of binding in this node so we pass the 
	// request down to the underlying layer. 
	return m_pTransportLayer->bind(url);
}

unique_ptr<Node> SSLNode::accept(){
	// the accept call is meaningless to SSL node itthis-> 
	// but if there is a connection from downline then we gladly serve it. 
	unique_ptr<Node> peer = m_pTransportLayer->accept();
	if(peer){
		unique_ptr<SSLNode> con(new SSLNode(m_pNetwork, move(peer), SOCK_SERVER));
		con->do_handshake();
		return move(con);
	}
	return unique_ptr<Node>();
}

int SSLNode::listen(const URL &url){
	if(this->state & CON_STATE_CONNECTED || this->server_socket == false){
		ERROR("CAN ONLY USE LISTEN ON A NON CONNECTED SERVER SOCKET!");
		return -1;
	}
	
	if(m_pTransportLayer->listen(url)>0){
		_init_ssl_socket(true);
		this->url = m_pTransportLayer->url;
		
		return 1;
	}
	return -1;
}

size_t SSLNode::input_pending() const{
	return m_DataBuffer.input_pending();
}

size_t SSLNode::output_pending() const{
	return BIO_ctrl_pending(write_buf);
}

void SSLNode::run(){
	
	//if(m_bProcessingMainLoop) return;
	//SETFLAG(m_bProcessingMainLoop, 0);
	
	if(state & CON_STATE_WAIT_CLOSE){
		
		m_pTransportLayer->close();
		this->state = CON_STATE_DISCONNECTED;
		
		LOG(1,"SSL: disconnected!");
	}
	
	m_pTransportLayer->run();
	
	// if we are waiting for connection and the downline has changed it's state
	// to being connected, we can now switch to handshake mode and do the handshake. 
	if((this->state & CON_STATE_INITIALIZED) && this->m_pSSL && this->m_pCTX && (m_pTransportLayer->state & CON_STATE_CONNECTED)){
		// switch into handshake mode
		this->url = URL("ssl", m_pTransportLayer->url.host(), m_pTransportLayer->url.port());
		
		this->timer = milliseconds();
		this->state = CON_STATE_SSL_HANDSHAKE; 
		LOG(1,"SSL: initializing handshake..");
	}
	
	// send / receive data between internal buffers and output 
	// but only if the connection is still valid. 
	if(!(state & CON_STATE_INVALID)){
		int rc = 0;
		char tmp[SOCKET_BUF_SIZE];
		
		while(BIO_ctrl_pending(this->write_buf)){
			if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
				LOG(3,"SSL: "<<this->url.url()<<" sending "<<rc<<" bytes of encrypted data. "<<hexencode(tmp, rc));
				m_pTransportLayer->send(tmp, rc);
			}
		}
		
		if((rc = m_pTransportLayer->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG(3,"SSL: "<<this->url.url()<<" received "<<rc<<" bytes of encrypted data. ");
			BIO_write(this->read_buf, tmp, rc);
		}
	}
	
	if(this->state & CON_STATE_CONNECTED){
		int rc; 
		char tmp[SOCKET_BUF_SIZE]; 
		if((rc = SSL_read(m_pSSL, tmp, SOCKET_BUF_SIZE))>0){
			LOG(3, "SSL: "<<url.url()<<" decrypted data "<<rc<<" bytes.");
			m_DataBuffer.sendOutput(tmp, rc);
		}
		if((rc = m_DataBuffer.recvOutput(tmp, SOCKET_BUF_SIZE, 0))>0){
			rc = SSL_write(this->m_pSSL, tmp, rc);
			LOG(3, "SSL: "<<url.url()<<" encrypting "<<rc<<" bytes.");
		}
	}
	
	// check if the async handshake is completed
	if(this->state & CON_STATE_SSL_HANDSHAKE){
		int res;
		
		// sometimes the underlying connection may fail or something else 
		// may happen that would make us forever stuck in handshake. 
		// we need to close if we stay here for too long.. 
		if((milliseconds()-this->timer) > CONNECTION_TIMEOUT){
			LOG(1,"SSL: connection timed out! "<<url.url());
			state = CON_STATE_DISCONNECTED;
			//this->close();
			return;
		}
		if(this->server_socket == false){
			//LOG(1,"SSL: Attempting to connect to "<<url.url());
			if((res = SSL_connect(this->m_pSSL))>0){
				this->state = CON_STATE_ESTABLISHED;
				this->url = URL("ssl", m_pTransportLayer->url.host(), m_pTransportLayer->url.port());
				LOG(1,"SSL: connection succeeded! Connected to peer "<<url.url());
			}
			else{
				//ERR_SSL(res);
			}
		}
		else {
			//LOG(1,"SSL: accepting ssl connections on "<<url.url());
			if((res=SSL_accept(this->m_pSSL))>0){
				this->state = CON_STATE_ESTABLISHED;
				this->url = URL("ssl", m_pTransportLayer->url.host(), m_pTransportLayer->url.port());
				LOG(1,"SSL: connection succeeded! Connected to peer "<<url.url());
			}
			else{
				//ERR_SSL(res);
			}
		}
	} 
	
	if(this->state & CON_STATE_CONNECTED && m_pTransportLayer->state & CON_STATE_DISCONNECTED){
		this->state = CON_STATE_DISCONNECTED; 
	}
	
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(m_pTransportLayer->state & CON_STATE_DISCONNECTED){
		LOG(1,"SSL: underlying connection lost. Disconnected!");
		this->state = CON_STATE_DISCONNECTED;
	}
}

void SSLNode::close(){
	this->state = CON_STATE_WAIT_CLOSE;
}
/*
SSLNode::SSLNode(weak_ptr<Network> net, unique_ptr<Node> out):Node(net){
	this->state = CON_STATE_INITIALIZED;
	
	this->m_pSSL = 0;
	this->m_pCTX = 0;
	
	m_pTransportLayer = move(out);
	
	this->read_buf = this->write_buf = 0;
	
	this->type = NODE_SSL;
}
*/
SSLNode::SSLNode(weak_ptr<Network> net, unique_ptr<Node> out, SocketType type):Node(net){
	this->state = CON_STATE_INITIALIZED;
	this->m_pSSL = 0;
	this->m_pCTX = 0;
	this->type = NODE_SSL;
	this->url = out->url;
	
	m_pTransportLayer = move(out);
	
	this->read_buf = this->write_buf = 0;
	
	server_socket = false;
		
	if(type == SOCK_SERVER){
		_init_ssl_socket(true);
	}
	else if(type == SOCK_CLIENT){
		_init_ssl_socket(false);
	}
	else {
		throw new std::exception();
	}
	timer = milliseconds();
	this->state = CON_STATE_SSL_HANDSHAKE;
}

SSLNode::~SSLNode(){
	if(!(this->state & CON_STATE_INVALID))
		this->close();
	
	_close_ssl_socket();
	
	LOG(3,"SSL: deleted "<<url.url());
}

/// for sending out encrypted data
/*
const SSLNode &operator>>(const SSLNode &self, Node *other){
	int rc;
	char tmp[SOCKET_BUF_SIZE];
	
	while(!BIO_eof(self.write_buf)){
		if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0){
			LOG(3,"SSL: "<<self.url.url()<<" sending "<<rc<<" bytes of encrypted data.");
			other->send(tmp, rc);
		}
	}
	return self;
}

/// for inputting encrypted data
SSLNode &operator<<(SSLNode &self, Node* other){
	int rc;
	char tmp[SOCKET_BUF_SIZE];
	
	if((rc = other->recv(tmp, SOCKET_BUF_SIZE))>0){
		LOG(3,"SSL: "<<self.url.url()<<" received "<<rc<<" bytes of encrypted data.");
		BIO_write(self.read_buf, tmp, rc);
	}
	return self;
}
*/
