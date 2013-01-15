#include "gclient.h"

///*******************************************
///********** SERVICE ************************
///*******************************************
/**
This model is used for both local and remote representation of the service
In local model we can have a socket where we accept connections and forward 
data to the remote end. On the remote end we can have a socket that connects 
to another host and relays information from that connection. **/

static void _socks_run(Service &self){
	struct sockaddr_in adr_clnt;  
	unsigned int len_inet = sizeof adr_clnt;  
	char buf[SOCKET_BUF_SIZE];
	int z;
	
	if((z = accept4(self.local_socket, (struct sockaddr *)&adr_clnt, &len_inet, SOCK_NONBLOCK))>0){
		LOG("[server socket] client connected!");
		
		/// read the first introduction specifying an ip address that we are connecting to
		struct socks_t{
			unsigned char version;
			unsigned char code;
			unsigned char reserved;
			unsigned char atype;
			char data[256];
		};
		uint16_t port;
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
				//hostent *hp = gethostbyname(socks.data);
				//memcpy((char *)&remote_addr, hp->h_addr, hp->h_length);
				break;
			} 
			case 4: // ipv6 address
				cout<<"IPv6 not supported!"<<endl;
				close(z);
		} 
		char host[256];
		unsigned char size = (unsigned char)socks.data[0];
		memcpy(host, socks.data+1, size);
		host[size] = 0;
		memcpy(&port, socks.data+1+size, sizeof(port));
		port = ntohs(port);
		LOG("SOCKS v"<<int(socks.version)<<", CODE: "<<int(socks.code)<<", AT:" <<
				int(socks.atype)<<", IP: "<<host<<":"<<port);
				
		// create the chain of routers that the new connection will be using
		// try to retreive the link from cache
		stringstream ss;
		ss<<host<<":"<<port;
		
		Connection *link = 0;
		/*if(self._cache.find(ss.str()) != self._cache.end()){
			(Link*)self._cache[ss.str()]
			link = (Link*)self._cache[ss.str()];
		}*/
		if(link == 0){
			link = NET_createTunnel(*self.net, host,port);
			self._cache[ss.str()] = link;
		}
		
		if(link){
			/// send success packet to the connected client
			socks.code = 0;
			socks.atype = 1;
			in_addr a;
			inet_aton("127.0.0.1", &a);
			memset(socks.data, 0, 6);
			//memcpy(socks.data, &a, 4);
			//memcpy(socks.data+4, &nport, 2);
			send(z, &socks, 10, 0);
			
			self.local_clients.push_back(pair<int, Connection*>(z, link));
			
			
			val = fcntl(z, F_GETFL, 0);
			fcntl(z, F_SETFL, val | O_NONBLOCK);
			
		}
		else {
			close(z);
		}
	}
	
	/// process data from local clients
	vector< pair<int, Connection*> >::iterator it = self.local_clients.begin();
	while(it != self.local_clients.end()){
		int sock = (*it).first;
		Connection *link = (*it).second;
		int rs;
		//if(select_socket(sock, 10) <= 0) continue;
		
		if((rs = recv(sock, buf, SOCKET_BUF_SIZE, 0)) > 0){
			link->send(*link, buf, rs);
		} 
		if(rs == 0){ // disconnected
			LOG("SOCKS: client disconnected!");
			close(sock);
			link->close(*link);
			it = self.local_clients.erase(it);
			continue;
		}
		if((rs = link->recv(*link, buf, SOCKET_BUF_SIZE))>0){
			LOG("sending "<<rs<<" bytes to socks connection!");
			if((rs = send(sock, buf, rs, MSG_NOSIGNAL))<0){
				
			}
		}
		it++;
		// try receiving data
	}
}

int _socks_listen(Service &self, const char *host, uint16_t port){
	int z;  
	int s;  
	struct sockaddr_in adr_srvr;  
	int len_inet;  
	int val;
	string str;
	
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

	
	self.local_socket = s;
	return 1;
	
close:
	close(s);
	return 0;
}

void SRV_initSOCKS(Service &self){
	self.initialized = true;
	self.listen = _socks_listen;
	self.run = _socks_run;
}

