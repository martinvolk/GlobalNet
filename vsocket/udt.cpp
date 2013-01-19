/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"

/***
Implementation of a normal UDT connection. Does not support any commands or packets. 
***/ 

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Node *UDTNode::accept(){
	UDTSOCKET recver;
	sockaddr_storage clientaddr;
	int addrlen = sizeof(clientaddr);
	
	/// accept connections on the server socket 
	if(UDT::ERROR != (recver = UDT::accept(this->socket, (sockaddr*)&clientaddr, &addrlen))){
		LOG("[udt] accepted incoming connection!");
		if(recver == UDT::INVALID_SOCK)
		{
			 cout << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
			 return 0;
		}
		
		Node *conn = new UDTNode();
		char clientservice[NI_MAXSERV];
		char host[NI_MAXHOST];
		
		getnameinfo((sockaddr *)&clientaddr, addrlen, host, sizeof(host), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);
		conn->host = host;
		conn->port = atoi(clientservice);
		conn->socket = recver;
		
		//LOG("[udt] accepted new connection!");
		conn->state = CON_STATE_ESTABLISHED;
		
		return conn;
	}
	return 0;
}

int UDTNode::connect(const char *hostname, uint16_t port){
	struct addrinfo hints, *local, *peer;
	
	
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = 0;
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
		LOG("[connection] incorrect server/peer address. " << hostname << ":" << port);
		return 0;
	}

	// connect to the server, implict bind
	if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
	{
		LOG("[connection] connect: " << UDT::getlasterror().getErrorMessage());
		return 0;
	}
		
	freeaddrinfo(peer);
	
	// set non blocking
	UDT::setsockopt(client, 0, UDT_RCVSYN, new bool(false), sizeof(bool));
	
	LOG("[udt] connected to "<<hostname<<":"<<port);
	
	this->socket = client; 
	this->host = inet_get_host_ip(hostname);
	this->port = port;
	
	this->state = CON_STATE_ESTABLISHED;
	return 1;
}

int UDTNode::send(const char *data, size_t size){
	return BIO_write(this->write_buf, data, size);
}
int UDTNode::recv(char *data, size_t size){
	return BIO_read(this->read_buf, data, size);
}

void UDTNode::run(){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	if(!(this->state & CON_STATE_CONNECTED)){
		//BIO_clear(this->write_buf);
		//BIO_clear(this->read_buf);
		return;
	}
	
	if(this->state & CON_STATE_CONNECTED){
		// send/recv data
		while(!BIO_eof(this->write_buf)){
			if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
				//LOG("UDT: sending "<<rc<<" bytes of data!");
				UDT::send(this->socket, tmp, rc, 0);
			}
		}
		if((rc = UDT::recv(this->socket, tmp, sizeof(tmp), 0))>0){
			//LOG("UDT: received "<<rc<<" bytes of data!");
			BIO_write(this->read_buf, tmp, rc);
		}
		// if disconnected
		if(UDT::getsockstate(this->socket) == CLOSED || UDT::getlasterror().getErrorCode() == UDT::ERRORINFO::ECONNLOST){
			LOG("UDT: "<<this->host<<":"<<this->port<<" "<<rc <<": "<< UDT::getlasterror().getErrorMessage());
			//UDT::close(this->socket);
			this->state = CON_STATE_DISCONNECTED;
		}
	}
}
int UDTNode::listen(const char *host, uint16_t port){
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

	if (UDT::ERROR == UDT::listen(socket, 10))
	{
		cout << "listen: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}
	
	// set socket as non blocking
	UDT::setsockopt(socket, 0, UDT_RCVSYN, new bool(false), sizeof(bool));
	
	LOG("[udt] peer listening on port " << port << " for incoming connections.");
	
	this->host = inet_get_host_ip(host);
	this->state = CON_STATE_LISTENING;
	this->port = port;
	this->socket = socket;
	
	return 1;
}

void UDTNode::peg(Node *other){
	ERROR("UDT is an ouput node. It can not be pegged!");
}

void UDTNode::close(){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	while(!BIO_eof(this->write_buf)){
		if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
			UDT::send(this->socket, tmp, rc, 0);
		}
	}
	LOG("UDT: disconnected!");
	UDT::close(this->socket);
	this->state = CON_STATE_DISCONNECTED;
}

UDTNode::UDTNode(){
	this->type = NODE_UDT;
}

UDTNode::~UDTNode(){
	this->close();
}
