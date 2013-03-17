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

/*
static int socket_writable(int socket){
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(socket, &fdset);
	
	timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 10;
	
	return select(1, 0, &fdset, 0, &tv);
}*/

int TCPNode::connect(const URL &url){
	struct hostent *hp;
	int s;
	
	if(url.port() != 80 && url.port() != 443){
		LOG(3, "Here!");
	}
	
	hp = gethostbyname(url.host().c_str());
	if (hp == NULL) {
		fprintf(stderr, "%s: unknown host\n", url.host().c_str());
		return -1;
	}
	memset((char *)&_socket_addr, 0, sizeof(_socket_addr));
	memcpy((char *)&_socket_addr.sin_addr, hp->h_addr, hp->h_length);
	//server.sin_len = sizeof(server);
	_socket_addr.sin_family = AF_INET;
	_socket_addr.sin_port = htons(url.port());
	s = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("socket");
		return -1;
	}
	
	int val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	this->state = CON_STATE_CONNECTING; 
	this->socket = s;
	
	this->url = url;
	
	LOG(1,"TCP: connecting to "<<url.url());
	// we set the state right away to established because the connect
	// call is blocking
	//this->state = CON_STATE_ESTABLISHED;
	
	return 1;
}

unique_ptr<Node> TCPNode::accept(){
	struct sockaddr_in adr_clnt;  
	unsigned int len_inet = sizeof adr_clnt;  
	char clientservice[32];
	
	int z;
	
	if(!(this->state & CON_STATE_LISTENING)){
		return unique_ptr<Node>();
	}
	if((z = accept4(this->socket, (struct sockaddr *)&adr_clnt, &len_inet, SOCK_NONBLOCK))>0){
		
		unique_ptr<TCPNode> con(new TCPNode(m_pNetwork));
		//NET_createConnection(this->net, "tcp", false);
		
		char host[NI_MAXHOST];
		getnameinfo((sockaddr *)&adr_clnt, len_inet, host, sizeof(host), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);
		con->url = URL(string("tcp://")+host+":"+string(clientservice));
		
		LOG(1,"TCP: incoming connection from "<<host<<":"<<clientservice);
		
		con->socket = z;
		con->state = CON_STATE_ESTABLISHED;
		
		int val = fcntl(z, F_GETFL, 0);
		fcntl(z, F_SETFL, val | O_NONBLOCK);
		
		return move(con);
	} else if(errno != EAGAIN) {
		//perror("accept");
	}
	return unique_ptr<Node>();
}

int TCPNode::listen(const URL &url){
	int z;  
	int s;  
	struct sockaddr_in adr_srvr;  
	int len_inet;  
	int val;
	int optval;
	string str;
	
	s = ::socket(AF_INET,SOCK_STREAM,0);  
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
	adr_srvr.sin_port = htons(url.port());

	z = ::bind(s,(struct sockaddr *)&adr_srvr,  len_inet);  
	if ( z == -1 )  {
		SOCK_ERROR("bind(2)"); 
		goto close;
	} 

	/* 
	* Set listen mode  
	*/  
	if ( ::listen(s, 10) == -1 ) {
		SOCK_ERROR("listen(2)");  
		goto close;
	}
	
	LOG(1,"[tcp local] now listening on port "<<url.port());
	
	optval = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

	val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	this->url = url;
	
	this->state = CON_STATE_LISTENING;
	this->socket = s;
	return 1;

close:
	::close(s);
	return 0;
}

int TCPNode::recv(char *data, size_t size, size_t minsize) const{
	if(m_Buffer.input_pending() == 0 || m_Buffer.input_pending() < minsize)  return 0;
	//m_Buffer.recv(data, size, minsize);
	return m_Buffer.recv(data, size, minsize);
	//vector<char> buf; buf.reserve(size); 
	//buf<<m_Buffer;
	//memcpy(data, &buf[0], size);
	//if(BIO_ctrl_pending(this->read_buf) < minsize) return 0;
	//int rc = BIO_read(this->read_buf, data, size);
	//if(rc>0)LOG(1,"TCP: recv "<<rc<<" bytes.");
	//return buf.size();
}

int TCPNode::send(const char *data, size_t size){
	// always do buffered because the conenction may not yet be connected!
	return m_Buffer.send(data, size); 
	//return BIO_write(this->write_buf, data, size);
}

void TCPNode::run(){
	Packet pack;
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	Node::run();
	
	if(this->state & CON_STATE_CONNECTING){
		if ((rc = ::connect(socket, (struct sockaddr*)&_socket_addr, sizeof(_socket_addr))) == -1
			&& (errno == EINPROGRESS || errno == EALREADY)) {
			// in progress 
			return;
		} else if(rc == 0){
			LOG(1,"TCP: successfully connected to "<<url.url());
			state = CON_STATE_ESTABLISHED; 
		} else {
			ERROR("TCP: connection failed to "<<url.url());
			::close(socket);
			state = CON_STATE_DISCONNECTED;
		}
	}
	/*
	if(this->state & CON_STATE_CONNECTING && socket_writable(this->socket)>0){
		this->state = CON_STATE_ESTABLISHED;
	
		LOG(1,"[tcp] connected to "<<url.url());
	}*/
	if(this->state & CON_STATE_CONNECTED){
		if((rc = ::recv(this->socket, tmp, sizeof(tmp), 0))>0){
			LOG(2,"TCP: received "<<rc<<" bytes of data from "<<url.url());
			m_Buffer.sendOutput(tmp, rc);
			//BIO_write(this->read_buf, tmp, rc);
		} 
		else if(rc == 0){
			LOG(3,"TCP: disconnected from "<<url.url());
			::close(this->socket);
			this->state = CON_STATE_DISCONNECTED;
		}
		else if(errno != ENOTCONN && errno != EWOULDBLOCK){
			//perror("recv");
		}
		
		if((rc = m_Buffer.recvOutput(tmp, SOCKET_BUF_SIZE))>0){
			int rs; 
			if((rs = ::send(this->socket, tmp, rc, MSG_NOSIGNAL))>0){
				LOG(2,"TCP: sent "<<rc<<" bytes of data to TCP socket "<<url.url());
			}
		} 
		
	}
}

void TCPNode::close(){
	this->state = CON_STATE_DISCONNECTED;
	
	::close(this->socket);
	LOG(1,"TCP: disconnected from "<<url.url());
}

TCPNode::TCPNode(weak_ptr<Network> net):Node(net){
	this->type = NODE_TCP;
}

TCPNode::~TCPNode(){
	LOG(3,"TCP: deleting "<<url.url());
	
	if(!(this->state & CON_STATE_DISCONNECTED))
		this->close();
}
