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
unique_ptr<Node> UDTNode::accept(){
	UDTSOCKET recver;
	sockaddr_storage clientaddr;
	int addrlen = sizeof(clientaddr);
	
	/// accept connections on the server socket 
	if(UDT::ERROR != (recver = UDT::accept(this->socket, (sockaddr*)&clientaddr, &addrlen))){
		LOG(1,"[udt] accepted incoming connection!");
		if(recver == UDT::INVALID_SOCK)
		{
			 cout << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
			 return unique_ptr<Node>();
		}
		
		unique_ptr<UDTNode> conn(new UDTNode(m_pNetwork));
		char clientservice[NI_MAXSERV];
		char host[NI_MAXHOST];
		
		getnameinfo((sockaddr *)&clientaddr, addrlen, host, sizeof(host), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);
		conn->url = URL("udt", host, atoi(clientservice));
		conn->socket = recver;
		
		//LOG(1,"[udt] accepted new connection!");
		conn->state = CON_STATE_ESTABLISHED;
		
		return move(conn);
	}
	return unique_ptr<Node>();
}

int UDTNode::connect(const URL &url){
	struct addrinfo hints, *local, *peer;
	
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = 0;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	stringstream ss;
	ss << CLIENT_BIND_PORT;
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
	
	//UDT::setsockopt(client, 0, UDT_RENDEZVOUS, new bool(true), sizeof(bool));
	/*if (UDT::ERROR == UDT::bind(client, local->ai_addr, local->ai_addrlen))
	{
		cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}*/
	

	freeaddrinfo(local);
	
	stringstream port_txt;
	port_txt << url.port();
	if (0 != getaddrinfo(url.host().c_str(), port_txt.str().c_str(), &hints, &peer))
	{
		LOG(1,"[connection] incorrect server/peer address. " << url.host() << ":" << url.port());
		return 0;
	}
	// set non blocking
	bool opt = false;
	UDT::setsockopt(client, 0, UDT_RCVSYN, &opt, sizeof(bool));
	
	// connect to the server, implict bind
	if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
	{
		ERROR("UDT: connect: " << UDT::getlasterror().getErrorMessage());
		return 0;
	}
	
	freeaddrinfo(peer);
	
	this->socket = client; 
	this->url = URL("udt", inet_get_host_ip(url.host()), url.port());
	
	this->state = CON_STATE_CONNECTING; 
	
	
	return 1;
}

int UDTNode::send(const char *data, size_t size){
	int rc; 
	if((rc = UDT::send(this->socket, data, size, MSG_NOSIGNAL))>0){
		LOG(3,"UDT: sent "<<rc<<" bytes of data to UDT socket "<<url.url());
	}
	return rc;
}
int UDTNode::recv(char *data, size_t size, size_t minsize) const{
	if(!m_ReadBuffer.input_pending() || m_ReadBuffer.input_pending() < minsize)  return 0;
	int rc = m_ReadBuffer.recv(data, size, minsize);
	LOG(3,"UDT: received "<<rc<<" bytes of data from UDT socket "<<url.url());
	return rc;
	//if(BIO_ctrl_pending(read_buf) < minsize) return 0;
	//return BIO_read(this->read_buf, data, size);
}

void UDTNode::run(){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	Node::run();
	
	UDTSTATUS status = UDT::getsockstate(socket);
	if(this->state & CON_STATE_CONNECTING && status == CONNECTED){
		LOG(1,"[udt] connected to "<<url.url());
		
		this->state = CON_STATE_ESTABLISHED;
	}
	else if(this->state & CON_STATE_CONNECTING && (status == BROKEN || status == CLOSED)){
		this->state = CON_STATE_DISCONNECTED;
	}
	
	if(!(this->state & CON_STATE_CONNECTED)){
		//BIO_clear(this->write_buf);
		//BIO_clear(this->read_buf);
		return;
	}
	
	if(this->state & CON_STATE_CONNECTED){
		// send/recv data
		if((rc = UDT::recv(this->socket, tmp, sizeof(tmp), 0))>0){
			m_ReadBuffer.sendOutput(tmp, rc);
			//LOG(1,"UDT: received "<<rc<<" bytes of data!");
			//BIO_write(this->read_buf, tmp, rc);
		}
		// if disconnected
		if(UDT::getsockstate(this->socket) == CLOSED || UDT::getlasterror().getErrorCode() == UDT::ERRORINFO::ECONNLOST){
			LOG(1,"UDT: "<<url.url()<<" "<<rc <<": "<< UDT::getlasterror().getErrorMessage());
			close();
		}
	}
}
int UDTNode::listen(const URL &url){
	addrinfo hints;
	addrinfo* res;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (0 != getaddrinfo(NULL, VSL::to_string(url.port()).c_str(), &hints, &res))
	{
		cout << "[info] Unable to listen on " << url.port() << ".. trying another port.\n" << endl;
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
		cout << "bind " << url.port() << ": " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}
	freeaddrinfo(res);

	if (UDT::ERROR == UDT::listen(socket, 10))
	{
		cout << "listen: " << UDT::getlasterror().getErrorMessage() << endl;
		return 0;
	}
	
	// set socket as non blocking
	bool opt = false;
	UDT::setsockopt(socket, 0, UDT_RCVSYN, &opt, sizeof(bool));
	
	LOG(1,"[udt] peer listening on port " << url.port() << " for incoming connections.");
	
	this->url = URL("udt", inet_get_host_ip(url.host()), url.port());
	
	this->state = CON_STATE_LISTENING;
	this->socket = socket;
	
	return 1;
}

void UDTNode::close(){
	this->state = CON_STATE_DISCONNECTED;
	
	if(this->socket)
		UDT::close(this->socket);
	socket = 0;
	LOG(3,"UDT: disconnected!");
}

UDTNode::UDTNode(weak_ptr<Network> net):Node(net){
	this->type = NODE_UDT;
	this->socket = 0;
}

UDTNode::~UDTNode(){
	LOG(3,"UDT: deleting "<<url.url());
	
	if(!(this->state & CON_STATE_DISCONNECTED))
		this->close();
}
