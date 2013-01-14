#include "gclient.h"

/***
Implementation of a normal UDT connection. Does not support any commands or packets. 
***/ 

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Connection *_udt_accept(Connection &self){
	UDTSOCKET recver;
	sockaddr_storage clientaddr;
	int addrlen = sizeof(clientaddr);
	
	/// accept connections on the server socket 
	if(UDT::ERROR != (recver = UDT::accept(self.socket, (sockaddr*)&clientaddr, &addrlen))){
		if(recver == UDT::INVALID_SOCK)
		{
			 cout << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
			 return 0;
		}
		
		Connection *conn = NET_allocConnection(*self.net);
		char clientservice[NI_MAXSERV];
		
		CON_initUDT(*conn, self.is_client);
		
		getnameinfo((sockaddr *)&clientaddr, addrlen, conn->host, sizeof(conn->host), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);
		conn->port = atoi(clientservice);
		conn->socket = recver;
		
		//LOG("[udt] accepted new connection!");
		conn->state = CON_STATE_ESTABLISHED;
		
		return conn;
	}
	return 0;
}

static int _udt_connect(Connection &self, const char *hostname, uint16_t port){
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
	
	self.socket = client; 
	string host = string("")+hostname;
	strncpy(self.host, host.c_str(), host.length());
	self.port = port;
	
	self.state = CON_STATE_ESTABLISHED;
	return 1;
}

static int _udt_send(Connection &self, const char *data, size_t size){
	return BIO_write(self.write_buf, data, size);
}
static int _udt_recv(Connection &self, char *data, size_t size){
	return BIO_read(self.read_buf, data, size);
}

static void _udt_run(Connection &self){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	//LOG("[udt] run "<<self.host<<":"<<self.port);
	/*
	int rc;
	rc = recv(s, buf, buffersize, 0);
	if (rc == 0)
	{
			// socket closed by remote host
			close(s); s=-1;
	}
	else if ((rc == -1) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)) )
	{
		 // need to wait.  Call select() or poll()
	}
	else if (rc == -1)
	{
			close(s); s=-1;
	}
	else
	{
			ProcessNewData(s, buffer, rc);
	}*/
	// send/recv data
	while(!BIO_eof(self.write_buf)){
		if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0){
			//LOG("UDT: sending "<<rc<<" bytes of data!");
			UDT::send(self.socket, tmp, rc, 0);
		}
	}
	if((rc = UDT::recv(self.socket, tmp, sizeof(tmp), 0))>0){
		//LOG("UDT: received "<<rc<<" bytes of data!");
		BIO_write(self.read_buf, tmp, rc);
	}
	// if disconnected
	if (UDT::ERROR == rc)
		{
			if(self.is_client && self.state != CON_STATE_LISTENING && UDT::getlasterror().getErrorCode() == 2002){
				LOG("UDT: " << (&self) << " "<<self.host<<":"<<self.port<<" "<<rc <<": "<< UDT::getlasterror().getErrorMessage());
				CON_close(self);
			}
		}
}
int _udt_listen(Connection &self, const char *host, uint16_t port){
	if(self.state != CON_STATE_UNINITIALIZED && self.state != CON_STATE_DISCONNECTED){
		//cout<<"CON_listen: connection has already been initialized. Please call CON_close() before establishing a new one!"<<endl;
	//	return 0;
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

	if (UDT::ERROR == UDT::listen(socket, 10))
	{
		cout << "listen: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}
	// set socket as non blocking
	UDT::setsockopt(socket, 0, UDT_RCVSYN, new bool(false), sizeof(bool));
	
	LOG("[udt] peer listening on port " << port << " for incoming connections.");
	
	self.state = CON_STATE_LISTENING;
	string str = string("")+host;
	memcpy(self.host, str.c_str(), min(ARRSIZE(self.host), str.length()));
	self.port = port;
	self.socket = socket;
	return 1;
}
void _udt_bridge(Connection &self, Connection *other){
	ERROR("UDT_bridge not implemented!");
}
void _udt_close(Connection &self){
	UDT::close(self.socket);
}

void _udt_on_data_received(Connection &self, const char *data, size_t size){
	ERROR("UDT_data_received not implemented!");
}

int CON_initUDT(Connection &self, bool client){
	CON_init(self);
	
	self.connect = _udt_connect;
	self.send = _udt_send;
	self.recv = _udt_recv;
	self.listen = _udt_listen;
	self.accept = _udt_accept;
	self.run = _udt_run;
	self.bridge = _udt_bridge;
	self.close = _udt_close;
	self.on_data_received = _udt_on_data_received;
	
	return 1;
}
