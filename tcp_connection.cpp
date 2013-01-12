#include "gclient.h"

static int _tcp_connect(Connection *self, const char *host, uint16_t port){
	struct sockaddr_in server;
	struct hostent *hp;
	int s;
	
	LOG("[tcp] connecting to "<<host<<":"<<port);
	if(self->_next){
		LOG("[connection] sending relay_connect.. "<<host);
		Packet pack;
		stringstream ss;
		ss<<"tcp:"<<string(host)<<string(":")<<port;
		string str = ss.str();
		pack.cmd.code = RELAY_CONNECT;
		pack.data.resize(str.length());
		memcpy(&pack.data[0], &str[0], str.length());
		self->_next->sendBlock(self->_next, pack);
		return 0;
	}
	hp = gethostbyname(host);
	if (hp == NULL) {
		fprintf(stderr, "%s: unknown host\n", host);
	}
	memset((char *)&server, 0, sizeof(server));
	memcpy((char *)&server.sin_addr, hp->h_addr, hp->h_length);
	//server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("socket");
		return -1;
	}
	/* Connect does the bind for us */
	if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("connect");
		return -1;
	}
	
	int val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	return s;
}

static Connection *_tcp_accept(Connection *self){
	struct sockaddr_in adr_clnt;  
	unsigned int len_inet = sizeof adr_clnt;  
	int z;
	Connection *con = 0;
	if((z = accept4(self->socket, (struct sockaddr *)&adr_clnt, &len_inet, SOCK_NONBLOCK))>0){
		LOG("[server socket] client connected!");
		
		con = new Connection();
		CON_initTCP(con, true);
		//NET_createConnection(self->net, "tcp", false);
		con->socket = z;
		
		int val = fcntl(z, F_GETFL, 0);
		fcntl(z, F_SETFL, val | O_NONBLOCK);
	} else if(errno != EAGAIN) {
		perror("accept");
	}
	return con;
}

static int _tcp_listen(Connection *self, const char *host, uint16_t port){
	if(self->state != CON_STATE_UNINITIALIZED && self->state != CON_STATE_DISCONNECTED){
		cout<<"CON_listen: connection has already been initialized. Please call CON_close() before establishing a new one!"<<endl;
		return 0;
	}
	
	int z;  
	int s;  
	struct sockaddr_in adr_srvr;  
	int len_inet;  
	int val;

	s = socket(AF_INET,SOCK_STREAM,0);  
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
	
	LOG("[tcp local] now listening on port "<<port);
	
	val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	self->socket = s;
	return 1;

close:
	close(s);
	return 0;
}

static int _tcp_recv(Connection *self, char *data, size_t size){
	if(self->_next)
		return self->_next->recv(self->_next, data, size);
	return BIO_read(self->read_buf, data, size);
}

static int _tcp_send(Connection *self, const char *data, size_t size){
	if(self->_next)
		return self->_next->send(self->_next, data, size);
	return BIO_write(self->write_buf, data, size);
}

static void _tcp_on_data_received(Connection *self, const char *data, size_t size){
	BIO_write(self->read_buf, data, size);
}

static void _tcp_run(Connection *self){
	Packet pack;
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	if(!self->is_client) return;
	
	if(self->_next && self->_next->recvBlock(self->_next, pack) > 0){
		if(pack.cmd.code == RELAY_CONNECT_OK){
			LOG("[tcp] remote tcp connection established!");
			self->state = CON_STATE_ESTABLISHED;
		}
	}
	
	
	// send/recv data
	while(!BIO_eof(self->write_buf)){
		if((rc = BIO_read(self->write_buf, tmp, SOCKET_BUF_SIZE))>0){
			LOG("TCP: sending "<<rc<<" bytes of data!");
			if((rc = send(self->socket, tmp, rc, MSG_NOSIGNAL))<0){
				perror("send");
			}
		}
	}
	if((rc = recv(self->socket, tmp, sizeof(tmp), 0))>0){
		LOG("TCP: received "<<rc<<" bytes of data!");
		BIO_write(self->read_buf, tmp, rc);
	}
	else if(errno != ENOTCONN && errno != EWOULDBLOCK){
		perror("recv");
	}
}

static void _tcp_bridge(Connection *self, Connection *other){
	if(self->_next || other->_prev){
		ERROR("You can not bridge to a connection that is a part of another link!");
		return;
	}
	self->_next = other;
}

int CON_initTCP(Connection *self, bool client){
	CON_init(self);
	

	self->connect = _tcp_connect;
	self->accept = _tcp_accept;
	self->send = _tcp_send;
	self->recv = _tcp_recv;
	self->listen = _tcp_listen;
	self->run  = _tcp_run;
	self->bridge = _tcp_bridge;
	self->on_data_received = _tcp_on_data_received;
	
	return 1;
}
