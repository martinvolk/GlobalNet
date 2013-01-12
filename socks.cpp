#include "gclient.h"

///*******************************************
///********** SERVICE ************************
///*******************************************
/**
This model is used for both local and remote representation of the service
In local model we can have a socket where we accept connections and forward 
data to the remote end. On the remote end we can have a socket that connects 
to another host and relays information from that connection. **/


static void _socks_run(Service *self){
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
				//hostent *hp = gethostbyname(socks.data);
				//memcpy((char *)&remote_addr, hp->h_addr, hp->h_length);
				break;
			} 
			case 4: // ipv6 address
				cout<<"IPv6 not supported!"<<endl;
				close(z);
		} 
		*(socks.data+strlen(socks.data)-1) = 0;
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

int _socks_listen(Service *self, const char *host, uint16_t port){
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

void SRV_initSOCKS(Service *self){
	self->listen = _socks_listen;
	self->run = _socks_run;
}

