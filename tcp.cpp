#include "gclient.h"

static int _tcp_connect(Connection &self, const char *host, uint16_t port){
	struct sockaddr_in server;
	struct hostent *hp;
	int s;
	
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
		return 0;
	}
	/* Connect does the bind for us */
	if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("connect");
		return 0;
	}
	
	int val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	self.socket = s;
	
	memcpy(self.host, host, min(ARRSIZE(self.host), strlen(host)));
	self.port = port;
	
	// we set the state right away to established because the connect
	// call is blocking
	self.state = CON_STATE_ESTABLISHED;
	LOG("[tcp] connected to "<<host<<":"<<port);
	
	return s;
}

static Connection *_tcp_accept(Connection &self){
	struct sockaddr_in adr_clnt;  
	unsigned int len_inet = sizeof adr_clnt;  
	char clientservice[32];
	
	int z;
	Connection *con = 0;
	if((z = accept4(self.socket, (struct sockaddr *)&adr_clnt, &len_inet, SOCK_NONBLOCK))>0){
		LOG("[server socket] client connected!");
		
		con = NET_allocConnection(*self.net);
		CON_initTCP(*con, true);
		//NET_createConnection(self.net, "tcp", false);
		
		getnameinfo((sockaddr *)&adr_clnt, len_inet, con->host, sizeof(con->host), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);
		con->port = atoi(clientservice);
		
		con->socket = z;
		con->state = CON_STATE_ESTABLISHED;
		
		int val = fcntl(z, F_GETFL, 0);
		fcntl(z, F_SETFL, val | O_NONBLOCK);
	} else if(errno != EAGAIN) {
		//perror("accept");
	}
	return con;
}

static int _tcp_listen(Connection &self, const char *host, uint16_t port){
	int z;  
	int s;  
	struct sockaddr_in adr_srvr;  
	int len_inet;  
	int val;
	int optval;
	string str;
	
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
	
	optval = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

	val = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, val | O_NONBLOCK);
	
	str = string("")+host;
	memcpy(self.host, str.c_str(), min(ARRSIZE(self.host), str.length()));
	self.port = port;
	
	self.state = CON_STATE_LISTENING;
	self.socket = s;
	return 1;

close:
	close(s);
	return 0;
}

static int _tcp_recv(Connection &self, char *data, size_t size){
	return BIO_read(self.read_buf, data, size);
}

static int _tcp_send(Connection &self, const char *data, size_t size){
	return BIO_write(self.write_buf, data, size);
}

static void _tcp_run(Connection &self){
	Packet pack;
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	if(!(self.state & CON_STATE_CONNECTED)) return;
	
	// send/recv data
	while(!BIO_eof(self.write_buf)){
		if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0){
			LOG("TCP: sending "<<rc<<" bytes of data to "<<self.host<<":"<<self.port);
			if((rc = send(self.socket, tmp, rc, MSG_NOSIGNAL))<0){
				perror("TCP send");
			}
		}
	}
	if((rc = recv(self.socket, tmp, sizeof(tmp), 0))>0){
		LOG("TCP: received "<<rc<<" bytes of data!");
		BIO_write(self.read_buf, tmp, rc);
	} else if(rc == 0){
		LOG("TCP: disconnected");
		self.state = CON_STATE_DISCONNECTED;
	}
	else if(errno != ENOTCONN && errno != EWOULDBLOCK){
		//perror("recv");
	}
}

static void _tcp_peg(Connection &self, Connection *other){
	ERROR("TCP is an output node! it can not be pegged.");
}

static void _tcp_close(Connection &self){
	if(self.socket)
		close(self.socket);
	self.state = CON_STATE_DISCONNECTED;
}

int CON_initTCP(Connection &self, bool client){
	CON_init(self);
	
	self.connect = _tcp_connect;
	self.accept = _tcp_accept;
	self.send = _tcp_send;
	self.recv = _tcp_recv;
	self.close = _tcp_close;
	self.listen = _tcp_listen;
	self.run  = _tcp_run;
	self.peg = _tcp_peg;
	
	return 1;
}
