#include "gclient.h"

Link *NET_allocLink(Network &self){
	for(uint c = 0;c< ARRSIZE(self.links); c++){
		if(self.links[c].initialized == false){
			self.links[c].initialized = true;
			return &self.links[c];
		}
	}
	return 0;
}
Connection *NET_allocConnection(Network &self){
	int count = 0;
	for(uint c = 0;c< ARRSIZE(self.sockets); c++) {
		if(self.sockets[c].initialized) count++;
	}
	LOG("[alloc_connection] currently "<<count<<" open connecitons!");
	
 	for(uint c = 0;c< ARRSIZE(self.sockets); c++){
		if(self.sockets[c].initialized == false){
			self.sockets[c].initialized = true;
			return &self.sockets[c];
		}
	}
	return 0;
}
Peer *NET_allocPeer(Network &self){
	for(uint c = 0;c< ARRSIZE(self.peers); c++){
		if(self.peers[c].initialized == false) {
			self.peers[c].initialized = true;
			return &self.peers[c];
		}
	}
	return 0;
}
Service *NET_allocService(Network &self){
	for(uint c = 0;c< ARRSIZE(self.services); c++){
		if(self.services[c].initialized == false){
			self.services[c].initialized = true;
			return &self.services[c];
		}
	}
	return 0;
}

void NET_free(Link *link){
	//LNK_shutdown(*link);
	link->initialized = false;
}

void NET_free(Connection *conn){
	LOG("NET_free: shutting down a connection!");
	CON_shutdown(*conn);
	conn->initialized = false;
}


Peer *NET_getRandomPeer(Network &self){
	Peer *peers[ARRSIZE(self.peers)];
	int count = 0;
	// find connected peers (this may be optimized later)
	for(uint c=0; c< ARRSIZE(self.peers); c++){
		if(self.peers[c].initialized && self.peers[c].socket && self.peers[c].socket->state == CON_STATE_ESTABLISHED){
			peers[count] = &self.peers[c];
			count ++;
		}
	}
	if(count == 0) return 0;
	return peers[rand()%count];
}
/**
Establish a link through the nodes specified in path. 
Path: [ip:port]>[ip:port]
**/

Connection *NET_createLink(Network &self, const string &path){
	vector<string> tokens;
	Connection *link = NET_allocConnection(self);
	CON_initLINK(*link);
	
	tokenize(path, ">", tokens);
	//Connection *prev_con = 0 ;
	
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
			Peer *peer = NET_getRandomPeer(self);
			if(!peer){
				ERROR("Link: could not create linkNo peers connected!");
				return 0;
			}
			host = peer->socket->host;
			//port = peer->socket->port;
		} 
		LOG("[link] establishing intermediate connection to "<<host<<":"<<port);
		link->connect(*link, host.c_str(), port);
	}
	return link;
}

Connection * NET_createTunnel(Network &self, const string &host, uint16_t port) {
	Connection *link = NET_createLink(self, "*");
	if(link){
		link->connect(*link, host.c_str(), port);
		return link;
	}
	return 0;
}

int NET_init(Network &self){
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings(); 
	OpenSSL_add_all_algorithms();
	
	// use this function to initialize the UDT library
	UDT::startup();
	
	for(uint c =0;c<ARRSIZE(self.links); c++) self.links[c].net = &self;
	for(uint c=0;c<ARRSIZE(self.services); c++)self.services[c].net = &self;
	for(uint c=0;c<ARRSIZE(self.sockets); c++)self.sockets[c].net = &self;
	
	self.server = NET_allocConnection(self);
	CON_initPeer(*self.server, false);
	
	// attempt to find an available listen port. 1000 alternatives should be enough
	for(int port = SERV_LISTEN_PORT; port <= SERV_LISTEN_PORT + 1000; port ++){
		if(self.server->listen(*self.server, "localhost", port))
			break;
		if(port == SERV_LISTEN_PORT + 1000){
			cout<<"ERROR no available listen ports left!"<<endl;
			return 0;
		}
	}
	
	return 1;
}

Connection *NET_connect(Network &self, const char *hostname, int port){
	Connection *conn = NET_allocConnection(self);
	Peer *peer = NET_allocPeer(self);
	
	// set up a new relay connection to the host
	CON_initPeer(*conn, true);
	conn->connect(*conn, hostname, port);
	peer->socket = conn;
	return conn;
}

int NET_run(Network &self) {
	// run all services
	for(uint c=0;c<ARRSIZE(self.services); c++){
		if(self.services[c].initialized)
			self.services[c].run(self.services[c]);
	}
	
	// send / recv data from all connections
	for(uint c=0;c<ARRSIZE(self.sockets); c++){
		if(self.sockets[c].initialized){
			self.sockets[c].run(self.sockets[c]);
			if(self.sockets[c].state & CON_STATE_DISCONNECTED){
				NET_free(&self.sockets[c]);
			}
		}
	}
	
	for(uint c=0;c<ARRSIZE(self.peers); c++){
		Peer *p = &self.peers[c];
		if(p->initialized && p->socket->state & CON_STATE_DISCONNECTED){
			NET_free(p->socket);
			p->initialized = false;
		}
	}
	
	Connection *client = 0;
	if((client = self.server->accept(*self.server))){
		cout << "[client] new connection: " << client->host << ":" << client->port << endl;
		Peer *peer = NET_allocPeer(self);
		peer->socket = client;
	}
	
	return 0;
}


Connection *NET_createCircuit(Network &self, unsigned int length = 3){
	stringstream ss;
	for(unsigned int c = 0;c<length;c++){
		ss<<"*";
		if(c!=length-1)
			ss<<">";	
	}
	
	Connection *link = NET_createLink(self, ss.str());
	return link;
}


void NET_publishService(Network &self, Service *srv){
	/// create a link to a random node in the network 
	/*
	srv->links.resize(3);
	for(int c=0;c<ARRSIZE(srv->links);c++){
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
	}*/
}

Connection *NET_createConnection(Network &self, const char *name, bool client){
	Connection *con = NET_allocConnection(self);
	if(strcmp(name, "peer")== 0){
		CON_initPeer(*con, client);
	}
	else if(strcmp(name, "tcp")==0){
		CON_initTCP(*con, client);
	}
	else if(strcmp(name, "udp")==0){
		CON_initUDT(*con, client);
	}
	else if(strcmp(name, "ssl")==0){
		CON_initSSL(*con, client);
	}
	else{
		ERROR("Unknown socket type '"<<name<<"'");
	}
	if(!con->initialized) return 0;
	return con;
}

Service *NET_createService(Network &self, const char *name){
	Service *svc = NET_allocService(self);
	if(strcmp(name, "socks")== 0){
		SRV_initSOCKS(*svc);
	}
	else if(strcmp(name, "console")==0){
		SRV_initCONSOLE(*svc);
	}
	else{
		ERROR("Unknown service '"<<name<<"'");
	}
	if(!svc->initialized) return 0;
	return svc;
}

void NET_shutdown(Network &self){
	// close services
	for(uint c=0;c<ARRSIZE(self.services); c++){
		//if(self.services[c].initialized)
			//SRV_shutdown(self.services[c]);
	}
	// close connections
	for(uint c=0;c<ARRSIZE(self.sockets); c++){
		if(self.sockets[c].initialized)
			CON_shutdown(self.sockets[c]);
	}
	
	// use this function to release the UDT library
	UDT::cleanup();
}
