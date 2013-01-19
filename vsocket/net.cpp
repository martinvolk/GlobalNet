/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"



int tokenize(const string& str, const string& delimiter, vector<string> &arr)
{
    int strleng = str.length();
    int delleng = delimiter.length();
    if (delleng==0)
        return 0;//no change

    int i=0;
    int k=0;
    while( i<strleng )
    {
        int j=0;
        while (i+j<strleng && j<delleng && str[i+j]==delimiter[j])
            j++;
        if (j==delleng)//found delimiter
        {
            arr.push_back(  str.substr(k, i-k) );
            i+=delleng;
            k=i;
        }
        else
        {
            i++;
        }
    }
    arr.push_back(  str.substr(k, i-k) );
    return arr.size();
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

double milliseconds(){
	struct timeval  tv;
	gettimeofday(&tv, NULL);

	return (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000 ; 
}

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
				ERROR("Link: could not create link! No peers connected!");
				return 0;
			}
			host = peer->socket->host;
			//port = peer->socket->port;
		} 
		LOG("[link] establishing intermediate connection to "<<host<<":"<<port);
		stringstream ss;
		ss<<"peer:"<<host<<":"<<port;
		link->connect(*link, ss.str().c_str(), 0);
	}
	return link;
}

Connection * NET_createTunnel(Network &self, const string &host, uint16_t port) {
	Connection *link = NET_createLink(self, "*>*");
	if(link){
		stringstream ss;
		ss<<"tcp:"<<host<<":"<<port;
		link->connect(*link, ss.str().c_str(), 0);
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
	CON_initPeer(*self.server);
	
	// attempt to find an available listen port. 1000 alternatives should be enough
	for(int port = SERV_LISTEN_PORT; port <= SERV_LISTEN_PORT + 1000; port ++){
		if(self.server->listen(*self.server, "localhost", port)){
			LOG("NET: peer listening on "<<self.server->host<<":"<<self.server->port);
			break;
		}
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
	CON_initPeer(*conn);
	conn->connect(*conn, hostname, port);
	peer->socket = conn;
	
	return conn;
}

static void _handle_command(Network &self, Connection *source, const Packet &pack){
	if(pack.cmd.code == CMD_PEER_LIST){
		vector<string> fields;
		LOG("NET: received active peer list "<<string(pack.data)<<", "<<pack.size());
		tokenize(pack.data, ";", fields);
		time_t packet_time = atol(fields[0].c_str());
		for(unsigned int c=1;c<fields.size();c++){
			vector<string> parts;
			tokenize(fields[c], ":", parts);
			if(parts.size() < 4){
				ERROR("Invalid format for the list of IPs.");
				return;
			}
			PeerRecord r; 
			r.hub_ip = parts[0];
			r.hub_port = atoi(parts[1].c_str());
			r.peer_ip = parts[2];
			r.peer_port = atoi(parts[3].c_str()); 
			r.last_update = time(0) - packet_time + atol(parts[4].c_str());
			self.peer_db.insert(r);
			LOG(r.hub_ip<<":"<<r.hub_port<<";"<<r.peer_ip<<":"<<r.peer_port);
		}
	} 
}

int NET_run(Network &self) {
	// run all services
	for(uint c=0;c<ARRSIZE(self.services); c++){
		if(self.services[c].initialized)
			self.services[c].run(self.services[c]);
	}
	
	// send / recv data from all connections
	for(uint c=0;c<ARRSIZE(self.sockets); c++){
		if(self.sockets[c].initialized)
			self.sockets[c].run(self.sockets[c]);
	}
	
	self.peer_db.purge();
	
	// update our listen record
	PeerRecord r; 	
	r.hub_ip = "";
	r.hub_port = 0;
	r.peer_ip = self.server->host;
	r.peer_port = self.server->port;
	r.is_local = false;
	r.last_update = time(0);
	
	self.peer_db.insert(r);
				
	// monitor peers for replies
	for(uint c = 0;c<ARRSIZE(self.peers);c++){
		Peer *p = &self.peers[c];
		Connection *s = p->socket;
		Packet pack;
		if(p->initialized && s && s->state & CON_STATE_CONNECTED){
			if(s->recvCommand(*s, &pack)){
				//LOG("NET: received command from "<<s->host<<":"<<s->port<<": "<<pack.cmd.code);
				_handle_command(self, s, pack);
			}
			// send some commands if it is time. 
			if(p->last_peer_list_submit < time(0) - NET_PEER_LIST_INTERVAL){
				// update the last_update times since we are still connected to this peer. 
				bool peer_ip_is_local = inet_ip_is_local(p->socket->host);
				bool peer_listen_address_is_peer_address = true;
				bool our_listen_ip_is_local = inet_ip_is_local(self.server->host);
				PeerRecord r; 
				
				r.hub_ip = self.server->host;
				r.hub_port = self.server->port;
				r.peer_ip = p->socket->host;
				r.peer_port = p->socket->port;
				r.is_local = peer_ip_is_local;
				r.last_update = time(0);
				
				if(r.peer_ip.compare("") != 0)
					self.peer_db.insert(r);
				
				// send a peer list to the peer 
				vector<PeerRecord> rand_set = self.peer_db.random(25);
				
				stringstream ss;
				ss<<time(0);
				for(int c=0;c< rand_set.size();c++){
					ss<<";"<<rand_set[c].hub_ip<<":"
						<<rand_set[c].hub_port<<":" 
						<<rand_set[c].peer_ip<<":"
						<<rand_set[c].peer_port<<":"
						<<rand_set[c].last_update;
				}
				LOG(ss.str());
				p->socket->sendCommand(*p->socket, CMD_PEER_LIST, ss.str().c_str(), ss.str().length());
	
				p->last_peer_list_submit = time(0);
			}
		}
	}

	
	// cleanup all unused objects
	for(uint c=0;c<ARRSIZE(self.sockets); c++){
		if(self.sockets[c].state & CON_STATE_DISCONNECTED)
			self.sockets[c].initialized = false;
	}
	for(uint c=0;c<ARRSIZE(self.peers); c++){
		Peer *p = &self.peers[c];
		if(p->initialized && p->socket->state & CON_STATE_DISCONNECTED)
			p->initialized = false;
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

Connection *NET_createConnection(Network &self, const char *name){
	Connection *con = NET_allocConnection(self);
	if(strcmp(name, "peer")== 0){
		CON_initPeer(*con);
	}
	else if(strcmp(name, "tcp")==0){
		CON_initTCP(*con);
	}
	else if(strcmp(name, "udt")==0){
		CON_initUDT(*con);
	}
	else if(strcmp(name, "ssl")==0){
		CON_initSSL(*con);
	}
	else{
		ERROR("Unknown socket type '"<<name<<"'");
	}
	if(!con->initialized) return 0;
	return con;
}
/*
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
}*/

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
