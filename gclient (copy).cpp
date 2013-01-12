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
#include <numeric>
#include <udt.h>
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
		case CON_STATE_LISTENING:
			return "CON_STATE_LISTENING";
		case CON_STATE_SSL_HANDSHAKE:
			return "CON_STATE_SSL_HANDSHAKE";
		case CON_STATE_ESTABLISHED:
			return "CON_STATE_ESTABLISHED";
		case CON_STATE_CLOSED:
			return "CON_STATE_CLOSED";
	}
	return "";
}

static void _con_flush(Connection *c){
	
}

/// handles io between physical connections and SSL buffers
void con_flush(Connection *c){
	c->_flush(c);
}

static int _con_init_ssl(Connection *c){
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

static void _con_connect_ssl(Connection *self){
	
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

/** Sets up basic structure for a connection of the desired protocol **/
void CON_init(Connection *c, RelayProtocol proto){
	c->state = CON_STATE_UNINITIALIZED;
	c->proto = proto;
	c->_flush = _con_flush;
	c->_on_recv_packet = 0;
	c->_bridge_prev = 0;
	c->_bridge_next = 0;
	_con_init_ssl(c);
}

/**
Establishes a new connection to the given host. Either an encrypted relay connection
or an unencrypted TCP or UDP connection to an arbitrary machine. 
**/
int CON_connect(Connection *conn, const char *hostname, int port){ 
	if(conn->state == CON_STATE_ESTABLISHED){
		cout<<"CON_connect: connection is already initialized. Please call CON_close() before establishing a new one!"<<endl;
		return 0;
	}
	// if bridged then we need to send a relay message and connect ssl after that
	if(conn->_bridge_next){
		// tell the remote end of the socket to connect instead of us
		
		LOG("[connection] sending relay_connect.. "<<hostname<<":"<<port);
		Packet pack;
		stringstream ss;
		ss<<string(hostname)<<string(":")<<port;
		string str = ss.str();
		pack.cmd.code = RELAY_CONNECT;
		pack.cmd.data_length = str.length();
		pack.data.resize(pack.cmd.data_length);
		memcpy(&pack.data[0], str.c_str(), str.length());
		CON_sendPacket(conn->_bridge_next, pack);
		return 1;
	}
	
	if(conn->proto == REL_PROTO_INTERNAL_CLIENT || conn->proto == REL_PROTO_INTERNAL_SERVER){
		_con_connect_internal(conn, hostname, port);
		_con_connect_ssl(conn);
	}
	else
		LOG("[connection] Set protocol is currently unsupported! ("<<conn->proto<<")");
	return -1;
}

int CON_listen(Connection *self, int port){
	if(self->state != CON_STATE_UNINITIALIZED && self->state != CON_STATE_CLOSED){
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
	UDT::close(self->socket);
}

/**
LOW LEVEL SEND
Send data through SSL. Data is put into a buffer and only sent to the network
upon the call to con_flush(). So remember to call con_flush() often. 
**/
int con_send(Connection *c, const char *buf, size_t size){
	if(c->state != CON_STATE_ESTABLISHED){
		cout<<"CON_send: connection is not established! Please call CON_connect() or CON_accept() to establish connection first."<<endl;
		return -1;
	}
	
	int ss;
	
	if((ss = SSL_write(c->con, buf, size))<=0){
		LOG("error sending ssl to "<<c->host<<":"<<c->port<<": "<<errorstring(SSL_get_error(c->con, ss)));
	}
	
	return ss;
}

/** 
LOW LEVEL RECV
Receive a chunk of data from SSL. If ssl does not have enough data to 
decrypt the buffer and block == true, the function blocks and waits
for data to become available. 
**/
int con_recv(Connection *c, char *rcv_buf, size_t size){
	int rs;
	
	if(c->state != CON_STATE_ESTABLISHED){
		cout<<"CON_recv: connection is not established! Please call CON_connect() or CON_accept() to establish connection first."<<endl;
		return -1;
	}
	
	if((rs = SSL_read(c->con, rcv_buf, size)) <= 0){
		// TODO: handle disconnect here
		// read could also fail simply because not enough data was received
		return 0;
	}
	return rs;
}

/** 
Takes a complete chunk of data and schedules it for transmission.
**/
int CON_sendPacket(Connection *self, const Packet &packet){
	LOG("[connection] CON_sendPacket: "<<self->host<<":"<<self->port<<" length: "<<packet.cmd.data_length<<" ");
	self->packet_out.push_back(packet);
	
	std::ostringstream os;
	os.fill('0');
	os<<std::hex;
	for(unsigned int c=0; c<packet.data.size();c++){
		unsigned char ch = packet.data[c];
		if(ch > 'A' && ch < 'z')
			os<<ch;
		else
			os<<'.';
	}
	LOG(os.str());
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
		LOG("[connection] CON_recvPacket: "<<self->host<<":"<<self->port<<" length: "<<packet.cmd.data_length);
		
		std::ostringstream os;
		os.fill('0');
		os<<std::hex;
		for(unsigned int c=0; c<packet.data.size();c++){
			char ch = packet.data[c];
			if(ch > 'A' && ch < 'z')
				os<<ch;
			else
				os<<'.';
		}
		LOG(os.str());
	
		return 1;
	}
	return 0;
}

void con_process(Connection *self){
	// receive a complete packet and store it in the packet buffer
	// if no complete packet is available, the function returns 0
	// important: the data may arrive in chunks. so we need to temporarily store 
	// a buffer with previous data and then extend it with new data until we
	// have a valid "packet". A valid packet needs to have valid checksum. 
	char tmp[SOCKET_BUF_SIZE];
	int rc;

	// handle data in/out through the udp socket unless we have another socket that we send data through
	if(!self->_bridge_next){
		rc = UDT::recv(self->socket, tmp, sizeof(tmp), 0);
		
		if(rc>0){
			LOG("[connection] con_flush: recieved "<<rc<<" bytes from "<<self->host<<":"<<self->port);
			BIO_write(self->read_buf, tmp, rc);
		}
		
		if(!BIO_eof(self->write_buf)){
			rc = BIO_read(self->write_buf, tmp, sizeof(tmp));
			
			if(rc>0){
				LOG("[connection] con_flush: sending "<<rc<<" bytes to "<<self->host<<":"<<self->port);
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
		if(self->bridge){
			char tmp[SOCKET_BUF_SIZE];
			int ss = UDT::recv(self->bridge, tmp, sizeof(tmp), 0);
		
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
		/// TODO: implement flood protection or some kind of timeout so we don't sit here for ever
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
					
					LOG("CON_process: received complete packet at "<<self->host<<":"<<self->port<<" cmd: "<<packet.cmd.code<<" datalength: "<<
					packet.cmd.data_length<<" recvsize: "<<self->_recv_buf.size());
					
					if(self->_on_recv_packet)
						self->_on_recv_packet(self, packet);
						
					// if we have an output socket then we write the received data directly to that socket
					//LOG(self->bridge);
					if(packet.cmd.code == CMD_DATA && self->bridge){
						UDT::send(self->bridge, &packet.data[0], packet.data.size(), 0); 
						LOG("[bridge] forwarded "<<packet.data.size()<<" bytes to external socket!");
					}
					// if we have a listener socket then we write the data to it's input buffer as well
					if(packet.cmd.code == CMD_DATA && self->_bridge_prev){
						LOG("[bridge] forwarding "<<packet.data.size()<<" bytes to internal socket "<<self->_bridge_prev->host<<":"<<self->_bridge_prev->port);
						BIO_write(self->_bridge_prev->read_buf, &packet.data[0], packet.data.size());
					}
					
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

/// encapsulates and sends and receives data through an underlying
/// bridge connection using the CMD_DATA packet
static void _bridge_flush(Connection *self){
	
	
}

static void _bridge_on_recv_packet(Connection *self, const Packet &pack){
	// write the data to the parent connection buffer if it's a data packet
	
}

int CON_bridge(Connection *self, Connection *other){
	/// make it so everything sent to bridge ends up as data packets sent through "other"
	if(self->proto == REL_PROTO_INTERNAL_CLIENT){
		self->_flush = _bridge_flush;
		self->_bridge_next = other;
		other->_bridge_prev = self;
		
		// signal the remote side that we are bridging
		Packet pack; 
		pack.cmd.code = CMD_BRIDGE_INIT;
		CON_sendPacket(other, pack);
		
		self->state = CON_STATE_SSL_HANDSHAKE;
		return 1;
	}
	/// make it so that all data packets received from "other" end up as packets of this
	else if(self->proto == REL_PROTO_INTERNAL_SERVER){
		self->_flush = _bridge_flush;
		self->_bridge_next = other;
		other->_bridge_prev = self;
		other->_on_recv_packet = _bridge_on_recv_packet;
		
		self->state = CON_STATE_SSL_HANDSHAKE;
		return 1;
	}
	return 0;
}

///*******************************************
///********** LINK LAYER *********************
///*******************************************
void LNK_init(Link *self, Connection *con){
	self->con = con;
}

/**
Writing data to a link stores it in the links write_buf
**/ 
int LNK_sendData(Link *self, const vector<char> &data) {
	Command cmd;
	cmd.code = CMD_DATA;
	cmd.data_length = data.size();
	vector<char> buf;
	buf.resize(sizeof(cmd)+data.size());
	memcpy(&buf[0], &cmd, sizeof(Command));
	memcpy(&buf[sizeof(cmd)], &data[0], data.size());
	LOG("writing "<<buf.size()<<" bytes to link "<<self->address.hex());
	self->write_buf.push_back(buf);
	return buf.size();
}

/** 
Reading data reads it from the links read_buf. Read buf is filled upon a flush
**/ 
int LNK_recvData(Link *self, vector<char> *data){
	if(self->con == 0 && self->read_buf.size()){
		LOG("LNK_recvData "<<self->address.hex()<<": "<<self->read_buf.size()<<endl);
		vector<char> &front = self->read_buf.front();
		Command *cmd = (Command*)&front[0];
		if(cmd->code == CMD_DATA && cmd->data_length == front.size()-sizeof(Command)){
			*data = vector<char>(front.begin()+sizeof(Command), front.end());
			self->read_buf.pop_front();
			return front.size()-sizeof(Command);
		}
	}
	return 0;
}

/** 
- Flushing a link means that it takes data from write_buf and sends it to the other end.
- Also it reads data from the other end and puts it into read_buf.
- If the other end is a local link then we can read data directly. 
**/
int LNK_flush(Link *self){
	// data needs to be sent
	if(self->write_buf.size()){
		LOG("flusing link!");
		for(deque< vector<char> >::iterator it = self->write_buf.begin();
			it != self->write_buf.end(); it++){
			if(self->local){
				self->local->read_buf.push_back(*it);
			} else if(self->con){
				//con_send(self->con, &(*it)[0], (*it).size());
			}
		}
		self->write_buf.clear();
	}
	// try to receive a packet from the connection
	return 1;
}
/** 
Creates a routed circuit to the destination through the machine that 
the link is already connected to.

Calling this function several times will establish a tunnel through the 
individual hosts that are supplied to this link function. 
**/ 
int NET_connectLink(Network *net, Link *src, const linkaddress_t &dest){
	// if the link is local then just connect the two links together
	map<string, Link*>::iterator it = net->links.find(dest.hex());
	if(it != net->links.end()){
		if(!it->second->con){
			src->local = it->second;
			LOG("connected link "<<src->address.hex()<<" to "<<dest.hex()<<endl);
			return 1;
		} else {
			// if the second link is stored locally but is directed at a remote host
		}
	}
	// the link was not found so we need to set the connection state to pending 
	// and send out requests to all our peers asking them whether they can route
	// this link for us. The link connection will be fully established
	// once a certain timeout is hit and enough peers have responded. 
	// the peer will reply with either CMD_CAN_ROUTE [address] or CMD_NO_ROUTE [address]
	// or nothing at all. We handle the CAN_ROUTE by adding the client to 
	// a list of hosts that can route this link. Then we can randomly pick 
	// which hosts to send the data through. The replies are handled in con_process();
	/// send link connection request to a handful of peers
	for(vector<Connection*>::iterator it = net->peers.begin(); 
			it != net->peers.end(); it++){
		Packet pack;
		pack.cmd.code = CMD_ASK;
		pack.cmd.data_length = sizeof(LINKADDRESS);
		pack.data.resize(sizeof(LINKADDRESS));
		memcpy(&pack.data[0], (const char*)&dest, sizeof(LINKADDRESS));
		CON_sendPacket(*it, pack);
	}
	return 0;
}

Link *NET_createLink(Network *net, const char *addrstr = NULL){
	// generate a random link key
	int id[2];
	id[0] = rand();
	id[1] = rand();
	LINKADDRESS addr;
	if(addrstr)
		addr.fromString(addrstr);
	else
		SHA1((const unsigned char*)&id, sizeof(id), (unsigned char*)&addr);
	if(net->links.find(addr.hex()) != net->links.end()){
		cout << "this should not happen but we just got a random number same as another link id!"<<endl;
		return net->links.find(addr.hex())->second;
	}
	Link *link = new Link();
	memcpy((unsigned char*)&link->address, &addr, sizeof(link->address));
	link->con = 0; // not connected to the network (links can also be local)
	link->local = 0;
	net->links[addr.hex()] = link;
	LOG("created link with id "<<addr.hex()<<" now "<<net->links.size()<<" links"<<endl);
	return link;
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

int NET_canRoute(Network *self, const LINKADDRESS &addr){
	return 1;
}


int net_run(Network *net) {
	
	// flush all links
	for(map<string, Link*>::iterator i = net->links.begin();
		i != net->links.end(); i++){
			LNK_flush((*i).second);
	}
	
	// send / recv data from all connections
	for(vector<Connection*>::iterator i = net->peers.begin(); i!= net->peers.end(); i++){
		con_flush(*i);
		con_process(*i);
		
		Packet packet, out;
		LINKADDRESS *addr;
		
		while(CON_recvPacket(*i, packet)){
			LOG("[con_process] received command "<< packet.data.size() << " " << packet.cmd.code << " len: " << packet.cmd.data_length);
			string str;
			switch(packet.cmd.code){
				/// peer is asking if we can route to hash
				/// [cmd_ask][data: 20 byte hash]
				case CMD_ASK:
				{
					// check if we can route packets to the desired destination
					// data contains a LINKADDRESS structure
					LOG("client asking if we can forward");
					addr = (LINKADDRESS*)&packet.data[0];
					if(NET_canRoute(net, *addr)){
						out.cmd.code = CMD_CAN_ROUTE;
						out.cmd.data_length = sizeof(LINKADDRESS);
						out.data.resize(sizeof(LINKADDRESS));
						memcpy(&out.data[0], addr, sizeof(LINKADDRESS));
						CON_sendPacket(packet.source, out);
					}
				}
				break;
				case CMD_BRIDGE_INIT: 
				{
					// initialize an outgoing connection
					//LOG("initializing bridge..");
					
				} break;
				case CMD_CAN_ROUTE:
				{
					// update the routing table with the new link id and connection
					LINKADDRESS *addr = (LINKADDRESS*)&packet.data[0];
					LOG("can route packet "<<addr->hex());
					break;
				}
				/// CONNECT to another host and relay through this host
				/// creates local Connection and sets current connection relay_socket to 
				/// the new connection. 
				case RELAY_CONNECT:
				{
					/// data is a host:port string
					string host = string(packet.data.begin(), packet.data.end());
					vector<string> tokens;
					tokenize(host, ":",tokens);
					
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
						return 0;
					}

					UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);
					// For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
					#ifdef WIN32
						UDT::setsockopt(client, 0, UDT_MSS, new int(1052), sizeof(int));
					#endif

					freeaddrinfo(local);
					
					if (0 != getaddrinfo(tokens[0].c_str(), tokens[1].c_str(), &hints, &peer))
					{
						cout << "incorrect server/peer address. " << tokens[0] << ":" << tokens[1] << endl;
						return 0;
					}

					// connect to the server, implict bind
					if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
					{
						cout << "connect bridge: " << UDT::getlasterror().getErrorMessage() << endl;
						return 0;
					}
						
					freeaddrinfo(peer);
					
					// set non blocking
					UDT::setsockopt(client, 0, UDT_RCVSYN, new bool(false), sizeof(bool));
					
					LOG("[relay] connecting to: "<<tokens[0]<<":"<<tokens[1]);
					
					(*i)->bridge = client;
				} break;
				/// received data that is to be forwarded to another connection
				/// [cmd_data][data: [int destination][int size][data]]
				case CMD_DATA:
					
					break;
				case CMD_TEST:
					cout << "data: "<< string(&packet.data[0]) << endl;
					break;
				default: 
					// unknown command so we 
					break;
			}
		}
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
				CON_sendPacket(*c, pack);
				//CON_sendPacket(conn, pack);
				//CON_sendPacket(conn, pack);
			}
			Connection *con = net_connect(&app->net, "localhost", 9000);
			CON_sendPacket(con, pack);
			Connection *bob = new Connection();
			CON_init(bob, REL_PROTO_INTERNAL_CLIENT);
			CON_bridge(bob, con);
			CON_connect(bob, "localhost", 9001);
			app->net.peers.push_back(bob);
			
			cout << "Sending test packet to bob.."<<endl;
			string str = "Hello BOB!";
			pack.cmd.code = CMD_DATA;
			pack.cmd.data_length = str.length();
			pack.data.resize(sizeof(Command)+pack.cmd.data_length);
			memcpy(&pack.data[0], str.c_str(), str.length());
			CON_sendPacket(bob, pack);
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
	enum  optionIndex { UNKNOWN, HELP, CONNECT };
	const option::Descriptor usage[] =
	{
		{UNKNOWN, 0,"" , ""    ,option::Arg::None, "USAGE: gclient -c [client:port,client2:port2] [--help]\n\n"
																							 "Options:" },
		{HELP,    0,"" , "help",option::Arg::None, "  --help  \tPrint usage and exit." },
		{CONNECT, 0,"c", "connect", (option::CheckArg)check_arg, "  --connect, -c  \tConnect to other peer [host:port]."},
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
