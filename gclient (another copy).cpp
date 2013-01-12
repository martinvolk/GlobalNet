#ifndef WIN32
   #include <unistd.h>
   #include <cstdlib>
   #include <cstring>
   #include <netdb.h>
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/sha.h>
  
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#else
   #include <winsock2.h>
   #include <ws2tcpip.h>
   #include <wspiapi.h>
   
#endif
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <arpa/inet.h>
#include <numeric>
#include <udt.h>
#include <fcntl.h>
#include "cc.h"
#include "optionparser.h"
#include "gclient.h"

using namespace std;



pthread_mutex_t gmutex = PTHREAD_MUTEX_INITIALIZER;
#ifndef WIN32
void* recvdata(void*);
#else
DWORD WINAPI recvdata(LPVOID);
#endif



int tokenize(const string& str,
                      const string& delimiters, vector<string> &tokens)
{
	// Skip delimiters at beginning.
	string::size_type lastPos = str.find_first_not_of(delimiters, 0);
	// Find first "non-delimiter".
	string::size_type pos     = str.find_first_of(delimiters, lastPos);

	while (string::npos != pos || string::npos != lastPos)
	{
			// Found a token, add it to the vector.
			tokens.push_back(str.substr(lastPos, pos - lastPos));
			// Skip delimiters.  Note the "not_of"
			lastPos = str.find_first_not_of(delimiters, pos);
			// Find next "non-delimiter"
			pos = str.find_first_of(delimiters, lastPos);
	}
  return tokens.size();
}
string errorstring(int e)
{
    switch(e) {
	case SSL_ERROR_NONE:
	    return "SSL_ERROR_NONE";
	case SSL_ERROR_SSL:
	    return "SSL_ERROR_SSL";
	case SSL_ERROR_WANT_READ:
	    return "SSL_ERROR_WANT_READ";
	case SSL_ERROR_WANT_WRITE:
	    return "SSL_ERROR_WANT_WRITE";
	case SSL_ERROR_WANT_X509_LOOKUP:
	    return "SSL_ERROR_WANT_X509_LOOKUP";
	case SSL_ERROR_SYSCALL:
	    return "SSL_ERROR_SYSCALL";
	case SSL_ERROR_ZERO_RETURN:
	    return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT:
	    return "SSL_ERROR_WANT_CONNECT";
	case SSL_ERROR_WANT_ACCEPT:
	    return "SSL_ERROR_WANT_ACCEPT";
	default:
	    char error[5];
	    sprintf(error, "%d", e);
	    return error;
    }
}

#define SERV_LISTEN_PORT 9000
#define ERR_SSL(err) if ((err)<=0) { cout<<errorstring(err)<<endl; ERR_print_errors_fp(stderr); }
#define SOCK_ERROR(what) { \
		if ( errno != 0 ) {  \
			fputs(strerror(errno),stderr);  \
			fputs("  ",stderr);  \
		}  \
		fputs(what,stderr);  \
		fputc( '\n', stderr); \
}

#define LOG(msg) { cout << msg << endl; }
//#define LOG(msg) 
//#define NO_SSL

#define CLIENT_CERT "client.crt"
#define CLIENT_KEY "client.key"
#define SERVER_KEY "server.key"
#define SERVER_CERT "server.crt"
//#define CA_CERT "ca.key"
#define SOCKET_BUF_SIZE 1024

///*******************************************
///********** CONNECTION *********************
///*******************************************

int CON_sendPacket(Connection*, const Packet&);

void con_show_certs(Connection *c){   
	SSL* ssl = c->con;
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

string con_state_to_string(ConnectionState state){
	switch(state){
		case CON_STATE_UNINITIALIZED:
			return "CON_STATE_UNINITIALIZED";
		case CON_STATE_CONNECTING:
			return "CON_STATE_CONNECTING";
		case CON_STATE_LISTENING:
			return "CON_STATE_LISTENING";
		case CON_STATE_SSL_HANDSHAKE:
			return "CON_STATE_SSL_HANDSHAKE";
		case CON_STATE_RELAY_PENDING:
			return "CON_STATE_RELAY_PENDING";
		case CON_STATE_ESTABLISHED:
			return "CON_STATE_ESTABLISHED";
		case CON_STATE_DISCONNECTED:
			return "CON_STATE_DISCONNECTED";
	}
	return "";
}


static int _con_init_ssl(Connection *c){
	// only do the ssl handshake for connections to other nodes
	if(c->proto != REL_PROTO_INTERNAL_CLIENT && c->proto != REL_PROTO_INTERNAL_SERVER)
		return 0; 
		
	bool client = (c->proto == REL_PROTO_INTERNAL_CLIENT)?true:false;
	
	if(client)
		c->ctx = SSL_CTX_new (SSLv3_client_method ());
	else
		c->ctx = SSL_CTX_new (SSLv3_server_method ());

	
	/* if on the client: SSL_set_connect_state(con); */
	if(client){
		SSL_CTX_use_certificate_file(c->ctx,CLIENT_CERT, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(c->ctx,CLIENT_KEY, SSL_FILETYPE_PEM);
		if ( !SSL_CTX_check_private_key(c->ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, 0);
		SSL_CTX_set_verify_depth(c->ctx,4);
	}
	else {
		SSL_CTX_use_certificate_file(c->ctx, SERVER_CERT, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(c->ctx, SERVER_KEY, SSL_FILETYPE_PEM);
		if ( !SSL_CTX_check_private_key(c->ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
		
		SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, 0);
		SSL_CTX_set_verify_depth(c->ctx,4);
	}
	
	c->con = SSL_new (c->ctx);
	
	/* set up the memory-buffer BIOs */
	c->read_buf = BIO_new(BIO_s_mem());
	c->write_buf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(c->read_buf, -1);
	BIO_set_mem_eof_return(c->write_buf, -1);

	/* bind them together */
	SSL_set_bio(c->con, c->read_buf, c->write_buf);

	return 1;
}

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
static int _con_connect_internal(Connection *conn, const char *hostname, int port){
	struct addrinfo hints, *local, *peer;
	
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_socktype = SOCK_DGRAM;

	stringstream ss;
	ss << SERV_LISTEN_PORT;
	if (0 != getaddrinfo(NULL, ss.str().c_str(), &hints, &local))
	{
		cout << "incorrect network address.\n" << endl;
		return 0;
	}

	UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);
	
	// UDT Options
	//UDT::setsockopt(client, 0, UDT_CC, new CCCFactory<CUDPBlast>, sizeof(CCCFactory<CUDPBlast>));
	//UDT::setsockopt(client, 0, UDT_MSS, new int(9000), sizeof(int));
	//UDT::setsockopt(client, 0, UDT_SNDBUF, new int(10000000), sizeof(int));
	//UDT::setsockopt(client, 0, UDP_SNDBUF, new int(10000000), sizeof(int));

	// Windows UDP issue
	// For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
	#ifdef WIN32
		UDT::setsockopt(client, 0, UDT_MSS, new int(1052), sizeof(int));
	#endif

	// for rendezvous connection, enable the code below
	/*
	UDT::setsockopt(client, 0, UDT_RENDEZVOUS, new bool(true), sizeof(bool));
	if (UDT::ERROR == UDT::bind(client, local->ai_addr, local->ai_addrlen))
	{
		cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}
	*/

	freeaddrinfo(local);
	
	stringstream port_txt;
	port_txt << port;
	if (0 != getaddrinfo(hostname, port_txt.str().c_str(), &hints, &peer))
	{
		cout << "[connection] incorrect server/peer address. " << hostname << ":" << port << endl;
		return 0;
	}

	// connect to the server, implict bind
	if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
	{
		cout << "[connection] connect: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}
		
	freeaddrinfo(peer);
	
	// set non blocking
	UDT::setsockopt(client, 0, UDT_RCVSYN, new bool(false), sizeof(bool));
	
	conn->socket = client; 
	strncpy(conn->host, hostname, sizeof(conn->host));
	conn->port = port;
	conn->state = CON_STATE_SSL_HANDSHAKE;
	return 1;
}

static int __callback_tcp_forward(Connection *self, const char *data, size_t size){
	return send(self->bridge, (void*)data, size, 0);
}
static int __callback_udt_forward(Connection *self, const char *data, size_t size){
	return UDT::send(self->bridge, data, size, 0);
}
static int __callback_tcp_receive(Connection *self, char *data, size_t size){
	return recv(self->bridge, (void*)data, size, 0);
}
static int __callback_udt_receive(Connection *self, char *data, size_t size){
	return UDT::recv(self->bridge, data, size, 0);
}


static int _udt_connect(const string &host, const string &port){
	struct addrinfo hints, *local, *peer;
	
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	stringstream ss;
	ss << SERV_LISTEN_PORT;
	if (0 != getaddrinfo(NULL, ss.str().c_str(), &hints, &local))
	{
		cout << "incorrect network address.\n" << endl;
		return -1;
	}

	UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);
	// For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
	#ifdef WIN32
		UDT::setsockopt(client, 0, UDT_MSS, new int(1052), sizeof(int));
	#endif

	freeaddrinfo(local);
	
	if (0 != getaddrinfo(host.c_str(), port.c_str(), &hints, &peer))
	{
		cout << "incorrect server/peer address. " << host << ":" << port << endl;
		return -1;
	}

	// connect to the server, implict bind
	if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
	{
		cout << "connect bridge: " << UDT::getlasterror().getErrorMessage() << endl;
		return -1;
	}
		
	freeaddrinfo(peer);
	
	// set non blocking
	UDT::setsockopt(client, 0, UDT_RCVSYN, new bool(false), sizeof(bool));
	return client;
}
static int _tcp_connect(const string &host, const string &port){
	struct sockaddr_in server;
	struct hostent *hp;
	int s;
	
	hp = gethostbyname(host.c_str());
	if (hp == NULL) {
		fprintf(stderr, "rlogin: %s: unknown host\n", host.c_str());
	}
	memset((char *)&server, 0, sizeof(server));
	memcpy((char *)&server.sin_addr, hp->h_addr, hp->h_length);
	//server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_port = htons(atoi(port.c_str()));
	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("rlogin: socket");
		return -1;
	}
	/* Connect does the bind for us */
	if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("rlogin: connect");
		return -1;
	}
	
	int val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	return s;
}


static void _con_send_error(Connection *self, ConnectionError err, const string &description){
	Packet pack;
	pack.cmd.code = RELAY_ERROR;
	pack.data.resize(description.size()+sizeof(ConnectionError));
	memcpy(&pack.data[0], &err, sizeof(ConnectionError));
	memcpy(&pack.data[sizeof(ConnectionError)], &description[0], description.length());
	CON_sendPacket(self, pack);
}
static void _con_send_message(Connection *self, ConnectionMessage msg){
	Packet pack;
	pack.cmd.code = msg;
	CON_sendPacket(self, pack);
}
/** Sets up basic structure for a connection of the desired protocol **/
void CON_init(Connection *c, RelayProtocol proto){
	c->state = CON_STATE_DISCONNECTED;
	c->proto = proto;
	c->_on_recv_packet = 0;
	c->_bridge_prev = 0;
	c->_bridge_next = 0;
	c->receive_data = __callback_udt_receive;
	c->forward_data = __callback_udt_forward;
	_con_init_ssl(c);
}

/**
Establishes a new connection to the given host. Either an encrypted relay connection
or an unencrypted TCP or UDP connection to an arbitrary machine. 
**/
void CON_connect(Connection *conn, const char *hostname, int port){ 
	if(conn->state == CON_STATE_ESTABLISHED){
		cout<<"CON_connect: connection is already initialized. Please call CON_close() before establishing a new one!"<<endl;
		return;
	}
	// if bridged then we need to send a relay message and connect ssl after that
	if(conn->_bridge_next){
		// tell the remote end of the socket to connect instead of us
		
		LOG("[connection] sending relay_connect.. "<<hostname<<":"<<port);
		Packet pack;
		stringstream ss;
		string proto = "";
		if(conn->proto == REL_PROTO_TCP)
			proto = "tcp:";
		ss<<proto<<string(hostname)<<string(":")<<port;
		string str = ss.str();
		pack.cmd.code = RELAY_CONNECT;
		pack.cmd.data_length = str.length();
		pack.data.resize(pack.cmd.data_length);
		memcpy(&pack.data[0], str.c_str(), str.length());
		CON_sendPacket(conn->_bridge_next, pack);
		// connection will be established once the relay responds with RELAY_CONNECT_OK
	}
	else if(conn->proto == REL_PROTO_INTERNAL_CLIENT || conn->proto == REL_PROTO_INTERNAL_SERVER){
		// establish a direct connection
		if(!_con_connect_internal(conn, hostname, port)){
			LOG("[error] error connecting to "<<hostname<<":"<<port);
		} 
	}
	else
		LOG("[connection] Set protocol is currently unsupported! ("<<conn->proto<<")");
}

int CON_listen(Connection *self, int port){
	if(self->state != CON_STATE_UNINITIALIZED && self->state != CON_STATE_DISCONNECTED){
		cout<<"CON_listen: connection has already been initialized. Please call CON_close() before establishing a new one!"<<endl;
		return 0;
	}
	
	addrinfo hints;
	addrinfo* res;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	
	stringstream ss;
	ss << port;

	if (0 != getaddrinfo(NULL, ss.str().c_str(), &hints, &res))
	{
		cout << "[info] Unable to listen on " << port << ".. trying another port.\n" << endl;
		return 0;
	}

	int socket = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	
	// UDT Options
	//UDT::setsockopt(serv, 0, UDT_CC, new CCCFactory<CUDPBlast>, sizeof(CCCFactory<CUDPBlast>));
	//UDT::setsockopt(serv, 0, UDT_MSS, new int(9000), sizeof(int));
	//UDT::setsockopt(serv, 0, UDT_RCVBUF, new int(10000000), sizeof(int));
	//UDT::setsockopt(serv, 0, UDP_RCVBUF, new int(10000000), sizeof(int));

	if (UDT::ERROR == UDT::bind(socket, res->ai_addr, res->ai_addrlen))
	{
		cout << "bind " << port << ": " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}

	freeaddrinfo(res);
	
	cout << "peer listening on port " << port << " for incoming connections." << endl;
	

	if (UDT::ERROR == UDT::listen(socket, 10))
	{
		cout << "listen: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}
	// set socket as non blocking
	UDT::setsockopt(socket, 0, UDT_RCVSYN, new bool(false), sizeof(bool));
	
	self->state = CON_STATE_LISTENING;
	self->socket = socket;
	return 1;
}


Connection *CON_accept(Connection *self){
	UDTSOCKET recver;
	sockaddr_storage clientaddr;
	int addrlen = sizeof(clientaddr);
	
	/// accept connections on the server socket 
	if(UDT::ERROR != (recver = UDT::accept(self->socket, (sockaddr*)&clientaddr, &addrlen))){
		if(recver == UDT::INVALID_SOCK)
		{
			 cout << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
			 return 0;
		}
		
		Connection *conn = new Connection();
		char clientservice[NI_MAXSERV];
		
		CON_init(conn, REL_PROTO_INTERNAL_SERVER);
		
		getnameinfo((sockaddr *)&clientaddr, addrlen, conn->host, sizeof(conn->host), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);
		conn->port = atoi(clientservice);
		conn->socket = recver;
		
		conn->state = CON_STATE_SSL_HANDSHAKE;
		
		return conn;
	}
	if(UDT::ERRORINFO::EASYNCRCV == UDT::getlasterror( ).getErrorCode( ))
		return 0;
	return 0;
}

void CON_close(Connection *self){
	if(self->socket)
		UDT::close(self->socket);
	if(self->bridge)
		close(self->bridge);
	if(self->_bridge_next){
		
	}
	if(self->_bridge_prev){
		
	}
	self->state = CON_STATE_DISCONNECTED;
}

/**
LOW LEVEL SEND
Send data through SSL. Data is put into a buffer and only sent to the network
upon the call to con_flush(). So remember to call con_flush() often. 
**/
int con_send(Connection *self, const char *buf, size_t size){
	if(self->state != CON_STATE_ESTABLISHED && self->state != CON_STATE_RELAY_PENDING){
		cout<<"CON_send: connection is not established! Please call CON_connect() or CON_accept() to establish connection first."<<endl;
		return -1;
	}
	int ss;
	// non internal connections are not using ssl to transmit data
	if(self->proto != REL_PROTO_INTERNAL_CLIENT && self->proto != REL_PROTO_INTERNAL_SERVER){
		ss = BIO_write(self->write_buf, buf, size);
	}
	else{
		if((ss = SSL_write(self->con, buf, size))<=0){
			LOG("error sending ssl to "<<self->host<<":"<<self->port<<": "<<errorstring(SSL_get_error(self->con, ss)));
			return -1;
		}
	}
	if(ss>0){
		LOG("[connection] send: "<<self->host<<":"<<self->port<<" length: "<<size<<" ");
		
		std::ostringstream os;
		os.fill('0');
		os<<std::hex;
		for(int c=0; c<ss;c++){
			unsigned char ch = buf[c];
			if(ch > 'A' && ch < 'z')
				os<<ch;
			else
				os<<'.';
		}
		LOG(os.str());
	}
	return ss;
}

/** 
LOW LEVEL RECV
Receive a chunk of data from SSL. If ssl does not have enough data to 
decrypt the buffer and block == true, the function blocks and waits
for data to become available. 
**/
int con_recv(Connection *self, char *rcv_buf, size_t size){
	int rs;
	
	if(self->state != CON_STATE_ESTABLISHED && self->state != CON_STATE_RELAY_PENDING){
		cout<<"CON_recv: connection is not established! Please call CON_connect() or CON_accept() to establish connection first."<<endl;
		return -1;
	}
	
	// non internal clients don't use ssl buffer
	if(self->proto != REL_PROTO_INTERNAL_CLIENT && self->proto != REL_PROTO_INTERNAL_SERVER){
		rs = BIO_read(self->read_buf, rcv_buf, size);
	}
	else{
		if((rs = SSL_read(self->con, rcv_buf, size)) <= 0){
			// TODO: handle disconnect here
			// read could also fail simply because not enough data was received
			return -1;
		}
	}
	if(rs>0){
		LOG("[connection] recv: "<<self->host<<":"<<self->port<<" length: "<<rs);
			
		std::ostringstream os;
		os.fill('0');
		os<<std::hex;
		for(int c=0; c<rs;c++){
			char ch = rcv_buf[c];
			if(ch > 'A' && ch < 'z')
				os<<ch;
			else
				os<<'.';
		}
		LOG(os.str());
	}
	return rs;
}

/** 
Takes a complete chunk of data and schedules it for transmission.
**/
int CON_sendPacket(Connection *self, const Packet &packet){
	Packet pack = packet;
	pack.cmd.data_length = packet.data.size();
	self->packet_out.push_back(pack);
	
	
	return 1;
}
/** 
Attempts to receive a packet. 
Note: do not ever call CON_recv() directly if you are using this function
**/ 
int CON_recvPacket(Connection *self, Packet &packet){
	if(self->packet_in.begin() != self->packet_in.end()){
		packet = self->packet_in.front();
		self->packet_in.pop_front();
	
		return 1;
	}
	return 0;
}

static void _con_handle_packet(Connection *self, const Packet &packet){
	/// forward data packets if we are connected to other sockets
	if(packet.cmd.code == CMD_DATA && self->bridge){
		self->forward_data(self, &packet.data[0], packet.data.size()); 
		LOG("[bridge] forwarded "<<packet.data.size()<<" bytes to external socket!");
	}
	// if we have a listener socket then we write the data to it's input buffer as well
	else if(packet.cmd.code == CMD_DATA && self->_bridge_prev){
		LOG("[bridge] forwarding "<<packet.data.size()<<" bytes to internal socket "<<self->_bridge_prev->host<<":"<<self->_bridge_prev->port);
		BIO_write(self->_bridge_prev->read_buf, &packet.data[0], packet.data.size());
	}
	
	/// we have received a request to extend our connection to another host
	else if(packet.cmd.code == RELAY_CONNECT){
		string str = string(packet.data.begin(), packet.data.end());
		vector<string> tokens;
		tokenize(str, ":",tokens);
		string proto = "udt";
		string host ;
		string port;
		if(tokens.size() == 3){
			proto = tokens[0];
			host = tokens[1];
			port = tokens[2];
		} else if(tokens.size() == 2){
			host = tokens[0];
			port = tokens[1];
		}
		int sock; 
		stringstream err;
		
		LOG("[relay] connecting to: "<<host<<":"<<port);
		if(proto == "udt"){
			sock = _udt_connect(host, port);
			if(sock > 0){
				self->bridge = sock;
				self->receive_data = __callback_udt_receive;
				self->forward_data = __callback_udt_forward;
				_con_send_message(self, RELAY_CONNECT_OK);
			} else {
				// failed
				err<<"Socket connection failed "<<host<<":"<<port;
				_con_send_error(self, REL_ERR_CON_FAILED, err.str());
			}
		} else if(proto == "tcp"){
			sock = _tcp_connect(host, port);
			if(sock > 0){
				self->bridge = sock;
				self->receive_data = __callback_tcp_receive;
				self->forward_data = __callback_tcp_forward;
				_con_send_message(self, RELAY_CONNECT_OK);
			} else{
				err<<"Socket connection failed "<<host<<":"<<port;
				_con_send_error(self, REL_ERR_CON_FAILED, err.str());
			}
		}
	}
	else if(packet.cmd.code == RELAY_CONNECT_OK){
		// signal to the bridged connection that it can start sending data
		if(self->_bridge_prev){
			LOG("[connection] relay connection succeeded. Now connected through the relay! ");
			self->_bridge_prev->state = CON_STATE_ESTABLISHED;
		} else {
			LOG("[error] received RELAY_CONNECT_OK, but connection is not bridged!");
		}
	}
	else if(packet.cmd.code == RELAY_ERROR){
		if(packet.data.size() > sizeof(ConnectionError)){
			ConnectionError err;
			
			LOG("[error] "+string(packet.data.begin()+sizeof(ConnectionError), packet.data.end()));
			memcpy(&err, &packet.data[0], sizeof(ConnectionError));
			
			if(err == REL_ERR_CON_FAILED){
				self->state = CON_STATE_DISCONNECTED;
			}
		}
	}
	else if(packet.cmd.code == RELAY_DISCONNECT){
		CON_close(self);
	}
}

void con_process(Connection *self){
	// receive a complete packet and store it in the packet buffer
	// if no complete packet is available, the function returns 0
	// important: the data may arrive in chunks. so we need to temporarily store 
	// a buffer with previous data and then extend it with new data until we
	// have a valid "packet". A valid packet needs to have valid checksum. 
	char tmp[SOCKET_BUF_SIZE];
	int rc;

	// send and receive data
	if(!self->_bridge_next){
		rc = UDT::recv(self->socket, tmp, sizeof(tmp), 0);
		
		if(rc>0){
			//LOG("[connection] con_flush: recieved "<<rc<<" bytes from "<<self->host<<":"<<self->port);
			BIO_write(self->read_buf, tmp, rc);
		}
		
		if(!BIO_eof(self->write_buf)){
			rc = BIO_read(self->write_buf, tmp, sizeof(tmp));
			
			if(rc>0){
				//LOG("[connection] con_flush: sending "<<rc<<" bytes to "<<self->host<<":"<<self->port);
				rc = UDT::send(self->socket, tmp, rc, 0);
			}
		} 
	}
	else {
		if(!BIO_eof(self->write_buf)){
			rc = BIO_read(self->write_buf, tmp, sizeof(tmp));
			
			if(rc>0){
				LOG("con_flush_bridge: sending "<<rc<<" bytes to "<<self->host<<":"<<self->port);
				Packet pack;
				pack.cmd.code = CMD_DATA;
				pack.cmd.data_length = rc;
				pack.data.resize(rc);
				memcpy(&pack.data[0], tmp, rc);
				CON_sendPacket(self->_bridge_next, pack);
			}
		}
	} 
	
	
	
	/// if waiting for ssl handshake then attempt to process it
	/// the handshake will only succeed when there is enough data
	if(self->state == CON_STATE_SSL_HANDSHAKE){
		int res;
		if(self->proto == REL_PROTO_INTERNAL_CLIENT){
			if((res = SSL_connect(self->con))>0){
				self->state = CON_STATE_ESTABLISHED;
				LOG("ssl connection succeeded! Connected to peer "<<self->host<<":"<<self->port);
			}
			else{
				ERR_SSL(SSL_get_error(self->con, res));
			}
		}
		else if(self->proto == REL_PROTO_INTERNAL_SERVER){
			if((res=SSL_accept(self->con))>0){
				self->state = CON_STATE_ESTABLISHED;
				LOG("ssl connection succeeded! Connected to peer "<<self->host<<":"<<self->port);
			}
			else
				ERR_SSL(SSL_get_error(self->con, res));
		}
	}
	
	/// if we have a connection to a peer
	if(self->state == CON_STATE_ESTABLISHED){
		/// if we have an external socket then read data from it and send it over as data packet to the other peer
		if(self->bridge && self->receive_data){
			char tmp[SOCKET_BUF_SIZE];
			int ss = self->receive_data(self, tmp, SOCKET_BUF_SIZE);
		
			if(ss>0){
				LOG("[bridge] con_flush: recieved "<<ss<<" bytes from external connection");
				Packet pack;
				pack.cmd.code = CMD_DATA;
				pack.cmd.data_length = ss;
				pack.data.resize(ss);
				memcpy(&pack.data[0], tmp, ss);
				// send over the bridged data unmodified to the other peer
				CON_sendPacket(self, pack);
			}
		} 
		
		// send all packets in the queue
		for(deque< Packet >::iterator it = self->packet_out.begin();
				it != self->packet_out.end(); it++){
			vector<char> pack;
			(*it).toVec(pack);
			con_send(self, &pack[0], pack.size());
		}
		self->packet_out.clear();
		
		// attempt to receive some data (non blocking) 
		if((rc = con_recv(self, tmp, sizeof(tmp)))>0){
			int start = self->_recv_buf.size();
			self->_recv_buf.resize(self->_recv_buf.size()+rc);
			memcpy(&self->_recv_buf[start], tmp, rc);
			
			// try to read as many complete packets as possible from the recv buf
			while(self->_recv_buf.size()){
				// now we need to check if the packet is complete
				Command *cmd = (Command*)&self->_recv_buf[0];
				Packet packet;
				if(cmd->data_length <= self->_recv_buf.size()-sizeof(Command)){
					// check checksum here
					if(cmd->data_length == self->_recv_buf.size()-sizeof(Command))
						packet.data = vector<char>(self->_recv_buf.begin()+sizeof(Command), self->_recv_buf.end());
					else
						packet.data = vector<char>(self->_recv_buf.begin()+sizeof(Command), self->_recv_buf.begin()+cmd->data_length+sizeof(Command));
					
					memcpy(&packet.cmd, cmd, sizeof(Command));
					packet.source = self;
					
					self->packet_in.push_back(packet);
					
					//LOG("CON_process: received complete packet at "<<self->host<<":"<<self->port<<" cmd: "<<packet.cmd.code<<" datalength: "<<
					//packet.cmd.data_length<<" recvsize: "<<self->_recv_buf.size());
					
					if(self->_on_recv_packet)
						self->_on_recv_packet(self, packet);
						
					// if we have an output socket then we write the received data directly to that socket
					//LOG(self->bridge);
					_con_handle_packet(self, packet);
					
					// update the recv_buf to only have the trailing data that has not 
					// yet been decoded. 
					self->_recv_buf = vector<char>(
						self->_recv_buf.begin()+cmd->data_length+sizeof(Command), 
						self->_recv_buf.end());
				} else {
					LOG("CON_process: received partial data of "<<rc<< " bytes "<<(self->_recv_buf.size()-sizeof(Command)));
					break;
				}
			}
		}
	}
}

static void _bridge_on_recv_packet(Connection *self, const Packet &pack){
	// write the data to the parent connection buffer if it's a data packet
	
}

void CON_bridge(Connection *self, Connection *other){
	self->_bridge_next = other;
	other->_bridge_prev = self;
	
	self->state = CON_STATE_DISCONNECTED;
	
	if(self->proto == REL_PROTO_INTERNAL_CLIENT){
		LOG("bridging client connection!");
		self->state = CON_STATE_SSL_HANDSHAKE;
	}
	else if(self->proto == REL_PROTO_INTERNAL_SERVER){
		LOG("bridgin server connection!");
		other->_on_recv_packet = _bridge_on_recv_packet;
		self->state = CON_STATE_SSL_HANDSHAKE;
	}
}

///*******************************************
///********** LINK LAYER *********************
///*******************************************

/**
Establish a link through the nodes specified in path. 
Path: [ip:port]>[ip:port]
**/
Link *NET_createLink(Network *net, const string &path){
	vector<string> tokens;
	Link *self = new Link();
	
	tokenize(path, ">", tokens);
	Connection *prev_con = 0 ;
	
	LOG(tokens.size());
	for(vector<string>::iterator it = tokens.begin(); it != tokens.end(); it++){
		vector<string> tmp;
		tokenize(*it, ":", tmp);
		string host;
		int port = 9000;
		if(tmp.size() == 2){
			host = tmp[0];
			port = atoi(tmp[1].c_str());
		} else if(tmp[0] == "*"){
			// pick random host from already connected peers (in the future make it pick from "known peers")
			Connection *peer = (net->peers[rand()%net->peers.size()]);
			host = peer->host;
			port = peer->port;
		}
		LOG("[link] establishing intermediate connection to "<<host<<":"<<port);
		Connection *node = new Connection();
		CON_init(node, REL_PROTO_INTERNAL_CLIENT);
		if(it != tokens.begin() && prev_con){
			
			CON_bridge(node, prev_con);
		}
		CON_connect(node, host.c_str(), port);
		prev_con = node;
		self->nodes.push_back(node);
	}
	net->links.push_back(self);
	return self;
}

/// starts a listening service for the local end of the link on the given port
/// all input on that port will be sent as data to the last hop.
int LNK_listenLocal(const string &host, int port){
	return 0;
}

void LNK_send(Link *self, const Packet &pack){
	// send it from the "back" of the link. A link is like a telescopic tunnel. Front is the end node. 
	CON_sendPacket(self->nodes[self->nodes.size()-1], pack);
}

/// starts a new connection on the remote end of the link 
/// arguments are host to connect to and port
int LNK_connect(Link *self, const string &host, int port, RelayProtocol proto){
	// create a new connection and make sure it originates from the remote host instead of the local one.
	Connection *con = new Connection();
	CON_init(con, proto);
	if(self->nodes.size())
		CON_bridge(con, (self->nodes[self->nodes.size()-1]));
	CON_connect(con, host.c_str(), port);
	
	self->nodes.push_back(con);
	
	/*
	// issue a relay connect to the end of the link. 
	// This will connect to the outside world allowing us to send CMD_DATA packets
	// to the outside server. 
	
	Packet pack;
	
	stringstream ss;
	ss<<"tcp:"<<host<<":"<<port;
	string str = ss.str();
	pack.cmd.code = RELAY_CONNECT;
	pack.data = vector<char>(str.begin(), str.end());
	LNK_send(self, pack);*/
	return 0;
}

/**
Writing data to a link stores it in the links write_buf
**/ 
int LNK_sendData(Link *self, const vector<char> &data) {
	Packet pack; 
	
	if(self->nodes.begin() == self->nodes.end()){
		cout<<"[error] can not send data to link because link has no nodes!"<<endl;
		return -1;
	}
	pack.cmd.code = CMD_DATA;
	pack.cmd.data_length = data.size();
	pack.data = data;
	return CON_sendPacket(self->nodes[self->nodes.size()-1], pack);
}

/** 
Reading data reads it from the links read_buf. Read buf is filled upon a flush
**/ 
int LNK_recvData(Link *self, vector<char> *data){
	Packet pack;
	while(CON_recvPacket((*self->nodes.begin()), pack)){
		cout << "LINK: received packet!"<<endl;
	}
	return 0;
}

void LNK_run(Link *self){
	for(vector<Connection*>::iterator it = self->nodes.begin();
			it != self->nodes.end(); it++){
		con_process(*it);
	}
}

///*******************************************
///********** SERVICE ************************
///*******************************************
/**
This model is used for both local and remote representation of the service
In local model we can have a socket where we accept connections and forward 
data to the remote end. On the remote end we can have a socket that connects 
to another host and relays information from that connection. **/

/**
Listens on a local port for connections to send to the other end */
int SRV_listenLocal(Service *self, const string &host, int port){
	int z;  
	int s;  
	struct sockaddr_in adr_srvr;  
	int len_inet;  
	int val;

	s = socket(PF_INET,SOCK_STREAM,0);  
	if ( s == -1 )  {
		SOCK_ERROR("socket()"); 
		goto close;
	} 

	/* 
	* Bind the server address  
	*/  
	len_inet = sizeof adr_srvr;  
	bzero((char *) &adr_srvr, sizeof(adr_srvr));
	adr_srvr.sin_family = AF_INET;
	adr_srvr.sin_addr.s_addr = INADDR_ANY;
	adr_srvr.sin_port = htons(port);

	z = bind(s,(struct sockaddr *)&adr_srvr,  len_inet);  
	if ( z == -1 )  {
		SOCK_ERROR("bind(2)"); 
		goto close;
	} 

	/* 
	* Set listen mode  
	*/  
	if ( listen(s, 10) == -1 ) {
		SOCK_ERROR("listen(2)");  
		goto close;
	}
	
	LOG("[server local] now listening on port "<<port);
	
	val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	self->local_socket = s;
	return 1;
	
close:
	close(s);
	return 0;
}

int SRV_initRemote(Service *self, const string &host, int port){
	return -1;
}

void SRV_run(Service *self){
	struct sockaddr_in adr_clnt;  
	unsigned int len_inet = sizeof adr_clnt;  
	char buf[SOCKET_BUF_SIZE];
	int z;
	
	if((z = accept4(self->local_socket, (struct sockaddr *)&adr_clnt, &len_inet, SOCK_NONBLOCK))>0){
		LOG("[server socket] client connected!");
		int random = rand();
		LINKADDRESS addr;
		SHA1((unsigned char*)&random, sizeof(int), (unsigned char*)addr.hash);
		self->local_clients[addr.hex()] = z;
		
		/// read the first introduction specifying an ip address that we are connecting to
		struct socks_t{
			unsigned char version;
			unsigned char code;
			unsigned char reserved;
			unsigned char atype;
			char data[256];
		};
		short port;
		socks_t socks;
		// recv method
		int val = fcntl(z, F_GETFL, 0);
		fcntl(z, F_SETFL, val & (~O_NONBLOCK));
		
		// get first packet
		recv(z, &socks, 2, 0);
		recv(z, &socks, sizeof(socks), 0);
		// return method 0 (no authentication)
		socks.version = 5;
		socks.code = 0;
		send(z, &socks, 2, 0);
		// receive a request header
		recv(z, &socks, sizeof(socks_t), 0);
		switch(socks.atype){
			case 1: // ipv4 address
				
			break; 
			case 3: // domain name
			{
				hostent *hp = gethostbyname(socks.data);
				//memcpy((char *)&remote_addr, hp->h_addr, hp->h_length);
				break;
			}
			case 4: // ipv6 address
				cout<<"IPv6 not supported!"<<endl;
				close(z);
		}
		memcpy(&port, socks.data+strlen(socks.data), sizeof(port));
		port = ntohs(port);
		LOG("SOCKS v"<<int(socks.version)<<", CODE: "<<int(socks.code)<<", AT:" <<int(socks.atype)<<", IP: "<<socks.data<<":"<<int(port));
		// create the chain of routers that the new connection will be using
		
		// this will create a link with local and remote end
		//Link *link = NET_createLink(&app->net, "localhost:9000");
		// connect to the outside host that we got in the request
		//LNK_connect(link, socks.data, port);
		//app->net.links.push_back(link);
		
		// send reply with bound local address and port for the connection
		socks.code = 0;
		short nport = htons(0);
		in_addr a;
		inet_aton("127.0.0.1", &a);
		memcpy(socks.data, &a, 4);
		memcpy(socks.data+4, &nport, 2);
		//send(z, &socks, sizeof(socks_t), 0);
		
		val = fcntl(z, F_GETFL, 0);
		fcntl(z, F_SETFL, val | O_NONBLOCK);
	}
	//else if ( z == -1 )  
	//	SOCK_ERROR("accept(2)");  
		
	/// process data from local clients
	for(map<string, int>::iterator it = self->local_clients.begin();
			it != self->local_clients.end();
			it++){
		int sock = (*it).second;
		int rs;
		if((rs = recv(sock, buf, SOCKET_BUF_SIZE, 0)) > 0){
			buf[rs] = 0;
			cout<<buf<<endl;
		}
		// try receiving data
	}
}

///*******************************************
///********** NETWORK ************************
///*******************************************

int net_init(Network *net){
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings(); 
	OpenSSL_add_all_algorithms();
	
	// use this function to initialize the UDT library
	UDT::startup();

	Connection *server = new Connection();
	CON_init(server, REL_PROTO_INTERNAL_SERVER);
	
	// attempt to find an available listen port. 1000 alternatives should be enough
	for(int port = SERV_LISTEN_PORT; port <= SERV_LISTEN_PORT + 1000; port ++){
		if(CON_listen(server, port))
			break;
		if(port == SERV_LISTEN_PORT + 1000){
			cout<<"ERROR no available listen ports left!"<<endl;
			delete server;
			return 0;
		}
	}
	net->server = server;
	
	return 0;
}

Connection *net_connect(Network *net, const char *hostname, int port){
	Connection *conn = new Connection();
	
	// set up a new relay connection to the host
	CON_init(conn, REL_PROTO_INTERNAL_CLIENT);
	CON_connect(conn, hostname, port);
	
	net->peers.push_back(conn);
	return conn;
}

int net_run(Network *net) {
	
	// flush all links
	for(vector<Link*>::iterator i = net->links.begin();
		i != net->links.end(); i++){
			LNK_run((*i));
	}
	
	// run all services
	for(vector<Service*>::iterator i = net->services.begin();
		i != net->services.end(); i++){
			SRV_run((*i));
	}
	// send / recv data from all connections
	for(vector<Connection*>::iterator i = net->peers.begin(); i!= net->peers.end(); i++){
		con_process(*i);
		
		Packet packet, out;
		/*
		while(CON_recvPacket(*i, packet)){
			//LOG("[con_process] received command "<< packet.data.size() << " " << packet.cmd.code << " len: " << packet.cmd.data_length);
			string str;
			switch(packet.cmd.code){
				
				case CMD_TEST:
					cout << "data: "<< string(&packet.data[0]) << endl;
					break;
				default: 
					// unknown command so we 
					break;
			}
		}*/
	}
	
	Connection *client = 0;
	if((client = CON_accept(net->server))){
		cout << "new connection: " << client->host << ":" << client->port << endl;
		
		net->peers.push_back(client);
	}
	
	return 0;
}

void net_destroy(Network *net){
	CON_close(net->server);

	// use this function to release the UDT library
	UDT::cleanup();
}



int check_arg(const option::Option& option, bool msg){
	return option::ARG_OK;
}

Link *NET_createCircuit(Network *self, unsigned int length = 3){
	stringstream ss;
	for(unsigned int c = 0;c<length;c++){
		ss<<"*";
		if(c!=length-1)
			ss<<">";
	}
	
	Link *link = NET_createLink(self, ss.str());
	return link;
}

Service *NET_connectToService(Network *self, const string &address){
	Service *serv = new Service ();
	serv->state = CON_STATE_CONNECTING;
	self->services.push_back(serv);
	return serv;
}

void NET_publishService(Network *self, Service *srv){
	/// create a link to a random node in the network 
	srv->links.resize(3);
	for(int c=0;c<3;c++){
		srv->links[c] = NET_createCircuit(self); 
	}
	
	/// store the service descriptor on the DHT
	stringstream ss;
	for(int c=0;c<3;c++){
		ss<<(*srv->links[c]->nodes.begin())->host<<":"<<(*srv->links[c]->nodes.begin())->port<<endl;
	}
	string str = ss.str();
	Packet pack;
	pack.cmd.code = DHT_STOR;
	pack.data.resize(str.length());
	for(int c=0;c<3;c++){
		//LNK_send(srv->links[c], pack);
	}
}

///*******************************************
///********** APPLICATION ********************
///*******************************************

void app_command(Application *app, string command){
	pthread_mutex_lock(&gmutex);
	LOG("adding command "<<command<< " to app queue;");
	app->commands.push_back(command);
	pthread_mutex_unlock(&gmutex);
}

void app_run(Application *app){
	net_run(&app->net);  // run all the data transfers and relays of data on the network
	
	pthread_mutex_lock(&gmutex);
	for(vector<string>::iterator i = app->commands.begin(); i!= app->commands.end(); i++){
		cout << "processing command " << *i << endl;
		if(*i == "listpeers"){
			for(vector<Connection*>::iterator c = app->net.peers.begin(); c != app->net.peers.end(); c++){
				cout << "connection: " << (*c)->host << ":"<<(*c)->port<<" state: "<<con_state_to_string((*c)->state)<<endl;
			}
			for(vector<Link*>::iterator l = app->net.links.begin(); l != app->net.links.end(); l++){
				cout << "link: "<<endl;
				for(vector<Connection*>::iterator c = (*l)->nodes.begin(); c != (*l)->nodes.end(); c++){
					cout << "    connection: " << (*c)->host << ":"<<(*c)->port<<" state: "<<con_state_to_string((*c)->state)<<endl;
				}
			}
			
		}
		else if(*i == "test"){
			// send an introduction packet
			cout << "Attempting to send test packets.."<<endl;
			Packet pack;
			
			for(vector<Connection*>::iterator c = app->net.peers.begin(); c != app->net.peers.end(); c++){
				cout << "Sending test packet.."<<endl;
				string str = "Hello World";
				pack.cmd.code = CMD_TEST;
				pack.cmd.data_length = str.length();
				pack.data.resize(sizeof(Command)+pack.cmd.data_length);
				memcpy(&pack.data[0], str.c_str(), str.length());
				//CON_sendPacket(*c, pack);
				//CON_sendPacket(conn, pack);
				//CON_sendPacket(conn, pack);
			}
			
			/// establish a rendezvous connection to a hidden service (started with -s)
			// this function starts the connection process. Once completed, the service state is set to SRV_STATE_ACTIVE
			// if the operation does not complete in due time, the state will be set to SRV_STATE_DISCONNECTED
			
			
			/// this code should accomplish the same thing as the code below
			
			Link *link = NET_createLink(&app->net, "localhost:9000");
			string str = "Hello Server!";
			vector<char> data(str.begin(), str.end());
			LNK_connect(link, "localhost", 3232, REL_PROTO_TCP);
			LNK_sendData(link, data);
			app->net.links.push_back(link);
			/*
			Connection *con = new Connection();
			CON_init(con, REL_PROTO_INTERNAL_CLIENT);
			CON_connect(con, "localhost", 9000);
			CON_sendPacket(con, pack);
			app->net.peers.push_back(con);
			Connection *bob = new Connection();
			CON_init(bob, REL_PROTO_INTERNAL_CLIENT);
			CON_bridge(bob, con);
			CON_connect(bob, "localhost", 9001);
			app->net.peers.push_back(bob);
			Connection *alice = new Connection();
			CON_init(alice, REL_PROTO_INTERNAL_CLIENT);
			CON_bridge(alice, bob);
			CON_connect(alice, "localhost", 9000);
			app->net.peers.push_back(alice);
			
			cout << "Sending test packet to bob.."<<endl;
			pack.cmd.code = CMD_DATA;
			pack.cmd.data_length = str.length();
			pack.data.resize(sizeof(Command)+pack.cmd.data_length);
			memcpy(&pack.data[0], str.c_str(), str.length());
			CON_sendPacket(alice, pack);*/
			/*
			LOG("testing to create a link");
			Link *link = NET_createLink(&app->net, "5014d1b320016c9557ebf1b44a2d301f90023e12");
			LINKADDRESS addr;
			addr.fromString("5014d1b320016c9557ebf1b44a2d301f90023e11");
			if(!NET_connectLink(&app->net, link, addr)){
				cout << "Could not connect link "<<link->address.hex()<<" to "<<addr.hex()<<endl;
			}
			cout<< "attempting to send data!"<<endl;
			const char *str = string("Hello World!").c_str();
			LNK_sendData(link, vector<char>(str, str + strlen(str)));
			*/
		}
	}
	app->commands.clear();
	pthread_mutex_unlock(&gmutex);
}

#ifndef WIN32
void* thread_gui(void* app)
#else
DWORD WINAPI thread_gui(LPVOID app)
#endif
{
	Application *aptr = (Application*)app;
	while(true){
		cout << ">> ";
		string cmd;
		cin >> cmd;
		cout << endl;
		app_command(aptr, cmd);
		cout << aptr->commands.size() << endl;
	}
	#ifndef WIN32
		return NULL;
	#else
		return 0;
	#endif
}

int main(int argc, char* argv[])
{
	enum  optionIndex { UNKNOWN, HELP, CONNECT, SERVICE };
	const option::Descriptor usage[] =
	{
		{UNKNOWN, 0,"" , ""    ,option::Arg::None, "USAGE: gclient -c [client:port,client2:port2] [--help]\n\n"
																							 "Options:" },
		{HELP,    0,"" , "help",option::Arg::None, "  --help  \tPrint usage and exit." },
		{CONNECT, 0,"c", "connect", (option::CheckArg)check_arg, "  --connect, -c  \tConnect to other peer [host:port]."},
		{SERVICE, 0,"s", "service", (option::CheckArg)check_arg, "  --service, -s  \tStart a default hidden service."},
		{UNKNOWN, 0,"" ,  ""   ,option::Arg::None, "\nExamples:\n"
																							 "  example --unknown -- --this_is_no_option\n"
																							 "  example -unk --plus -ppp file1 file2\n" },
		{0,0,0,0,0,0}
	};
	
	Application app;
	Network *net = &app.net;
	
  argc-=(argc>0); argv+=(argc>0); // skip program name argv[0] if present
	option::Stats  stats(usage, argc, argv);
	option::Option options[stats.options_max], buffer[stats.buffer_max];
	option::Parser parse(usage, argc, argv, options, buffer);

	if (parse.error()){
	 option::printUsage(std::cout, usage);
	 return 0;
	}
	
	if (options[HELP]) {
	 option::printUsage(std::cout, usage);
	 return 0;
	}
	
	net_init(net);
	
	// find all peers
	if(options[CONNECT].count() > 0){
		vector<string> peers;
		tokenize(string(options[CONNECT].first()->arg), string(","), peers);
		for(vector<string>::iterator i = peers.begin(); i!=peers.end();i++){
			vector<string> peer;
			tokenize(*i, string(":"), peer);
			int port = 9000;
			if(peer.size() > 1)
				port = atoi(peer[1].c_str());
				
			// this will extend the network with actual physical peers identified by an IP address. 
			net_connect(net, peer[0].c_str(), port);
		}
	}
	
	if(options[SERVICE].count() > 0){
		Service *service = NET_connectToService(net, "service id");
		SRV_listenLocal(service, "localhost", 8000);
	}
	#ifndef WIN32
		 pthread_t guithread;
		 pthread_create(&guithread, NULL, thread_gui, &app);
		 pthread_detach(guithread);
	#else
		 CreateThread(NULL, 0, thread_gui, &app, 0, NULL);
	#endif
	
	/*
	Link *link1 = NET_createLink(net, "f129b156150c26517dab594f717a1a75702e92b2");
	Link *link2 = NET_createLink(net, "5014d1b320016c9557ebf1b44a2d301f90023e09");
	if(options[CONNECT].count() > 0){
		// on client
		NET_createLink(net, "5014d1b320016c9557ebf1b44a2d301f90023e10");
	} else{
		// on server
		NET_createLink(net, "5014d1b320016c9557ebf1b44a2d301f90023e11");
	}
	if(!NET_connectLink(net, link1, link2->address)){
		cout << "Could not connect link "<<link1->address.hex()<<" to "<<link2->address.hex()<<endl;
	}
	cout<< "attempting to send data!"<<endl;
	const char *str = string("Hello World!").c_str();
	LNK_sendData(link1, vector<char>(str, str + strlen(str)));
	net_run(net);
	vector<char> data;
	cout << "attempting to receive data!"<<endl;
	if(LNK_recvData(link2, &data)){
		cout << "received from "<<link2->address.hex()<<" data: "<<std::accumulate(data.begin(), data.end(), std::string())<<endl;
	}
	*/
	
	
	/*
	LNK_open("hash"); 
	LNK_establish("peer1:port>peer2:port>peer3:port"); // only peer3 will get link descriptor
	LNK_send(link, data); // data goes to peer3 message queue 
	
	// on another machine
	LNK_open("randomkey");
	LNK_establish("relay1:port>relay2:port>peer3:port"); 
	LNK_connect("hash"); // connects to another link on peer3
	
	//connect to a remote host
	LNK_open("hash2");
	LNK_listen("localhost:1000");
	LNK_establish("relay1:port>relay2:port>peer3:port");
	LNK_connect("www.google.com", 80); // connects from peer3 to google (equivalent of just doing the same on peer3)
	
	// calling link connect on a newly created link, creates a direct connection without intermediate relays
	LNK_open("randomkey");
	LNK_connect("www.google.com", 80);
	LNK_send(link, data); // sends data to google
	LNK_recv(link, data); // recvs data from google socket. 
	*/
	while(true){
		// run main loop 
		app_run(&app);
		usleep(10000); // about 100fps
	}
	
	net_destroy(net);
	
	return 1;
}

#ifndef WIN32
void* recvdata(void* usocket)
#else
DWORD WINAPI recvdata(LPVOID usocket)
#endif
{
	Connection conn = *(Connection *)usocket;
	delete (Connection*)usocket;
  
	cout << "[thread] new thread started for client!" << endl;
	while(true){
		// just process the queue
		//con_process(&conn);
	}

	// TODO close stuff

	#ifndef WIN32
		return NULL;
	#else
		return 0;
	#endif
}
