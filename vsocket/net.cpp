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
/*
Link *Network::allocLink(){
	for(uint c = 0;c< ARRSIZE(this->links); c++){
		if(this->links[c].initialized == false){
			this->links[c].initialized = true;
			return &this->links[c];
		}
	}
	return 0;
}*/
/*
Node *Network::allocConnection(){
	int count = 0;
	for(uint c = 0;c< ARRSIZE(this->sockets); c++) {
		if(this->sockets[c].initialized) count++;
	}
	LOG("[alloc_connection] currently "<<count<<" open connecitons!");
	
 	for(uint c = 0;c< ARRSIZE(this->sockets); c++){
		if(this->sockets[c].initialized == false){
			this->sockets[c].initialized = true;
			return &this->sockets[c];
		}
	}
	return 0;
}
*/
/*
Peer *Network::createPeer(){
	Peer *node = new VSLNode(0);
	peers.push_back(new Peer(node));
	return node;
}
*/
Network::Peer *Network::getRandomPeer(){
	int r = rand() % peers.size();
	LOG("=================> USING PEER "<<r);
	if(!peers.size()) return 0;
	int c=0;
	for(list<Peer*>::iterator it = peers.begin();
			it != peers.end(); it++){
		if(r == c) return (*it);
		c++;
	}
	return 0;
}
/**
Establish a link through the nodes specified in path. 
Path: [ip:port]>[ip:port]
**/

LinkNode *Network::createLink(const string &path){
	vector<string> tokens;
	if(peers.size() == 0){
		ERROR("NET: not enough peers to build a link!");
		return 0;
	}
	
	LinkNode *link = new LinkNode();
	
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
			vector<PeerDatabase::Record> random = this->peer_db.random(1);
			if(!random.size()){
				ERROR("Link: could not create link! No peers connected!");
				return 0;
			}
			host = random[0].peer.ip;
			port = random[0].peer.port;
		} 
		LOG("[link] establishing intermediate connection to "<<host<<":"<<port);
		stringstream ss;
		ss<<"peer:"<<host<<":"<<port;
		link->connect(ss.str().c_str(), 0);
	}
	return link;
}

LinkNode * Network::createTunnel(const string &host, uint16_t port) {
	LinkNode *link = this->createLink("*>*");
	if(link){
		stringstream ss;
		ss<<"tcp:"<<host<<":"<<port;
		link->connect(ss.str().c_str(), 0);
		return link;
	}
	return 0;
}

Network::Network(){
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings(); 
	OpenSSL_add_all_algorithms();
	
	// use this function to initialize the UDT library
	UDT::startup();
	
	this->server = new VSLNode(0);
	
	vector< pair<string, string> > ifs = inet_get_interfaces();
	string listen_adr = "127.0.0.1";
	
	INFO("Available interfaces:");
	for(int c =0; c<ifs.size(); c++){
		INFO(ifs[c].first<<": "<<ifs[c].second);
		if(ifs[c].second.compare("127.0.0.1") != 0)
			listen_adr = ifs[c].second;
	}
	// attempt to find an available listen port. 1000 alternatives should be enough
	for(int port = SERV_LISTEN_PORT; port <= SERV_LISTEN_PORT + 1000; port ++){
		if(this->server->listen(listen_adr.c_str(), port)){
			LOG("NET: peer listening on "<<this->server->host<<":"<<this->server->port);
			break;
		}
		if(port == SERV_LISTEN_PORT + 1000){
			ERROR("ERROR no available listen ports left!");
		}
	}
	
	// blacklist our own address from local peer database to avoid localhost connections
	peer_db.blacklist(listen_adr);
}


void Network::connect(const char *hostname, int port){
	VSLNode *node = new VSLNode(0);
	node->connect(hostname, port);
	peers.push_back(new Peer(node));
	PeerDatabase::Record r;
	r.peer.ip = inet_get_ip(hostname);
	r.peer.port = port;
	peer_db.insert(r);
}

void Network::run() {
	//this->peer_db.purge();
	
	PeerDatabase::Record r;
	r.peer.ip = this->server->host;
	r.peer.port = this->server->port;
	peer_db.insert(r);
	
	// monitor peers for replies
	for(list<Peer*>::iterator it = peers.begin(); 
			it != peers.end(); ){
		Peer *p = (*it);
		Packet pack;
		
		// remove peers that have disconnected 
		if(p->is_disconnected()){
			delete p;
			peers.erase(it++);
			continue;
		}
		p->run();
		if(p->is_connected()){
			if(p->socket->recvCommand(&pack)){
				//LOG("NET: received command from "<<s->host<<":"<<s->port<<": "<<pack.cmd.code);
				if(pack.cmd.code == CMD_PEER_LIST){
					LOG("NET: received active peer list "<<string(pack.data)<<", "<<pack.size());
					
					peer_db.from_string(string(pack.data));
				} 
			}
			// send some commands if it is time. 
			if(p->last_peer_list_submit < time(0) - NET_PEER_LIST_INTERVAL){
				LOG("NET: sending peer list to the peer.");
				
				// update the last_update times since we are still connected to this peer. 
				bool peer_ip_is_local = inet_ip_is_local(p->socket->host);
				bool peer_listen_address_is_peer_address = true;
				bool our_listen_ip_is_local = inet_ip_is_local(this->server->host);
				
				// update the record of the current peer in the database 
				PeerDatabase::Record r; 
				// we add the peer to the database if he has provided a listen address
				// the database will automatically check if it's valid later. 
				if(p->listen_addr.is_valid()){
					r.peer = p->listen_addr;
				}
				else {
					// peer does not have a dedicated listening socket. 
					// we put the peer into database, but supply our own address as relay host
					r.peer = PeerAddress(p->socket->host, CLIENT_BIND_PORT);
					r.hub = PeerAddress(this->server->host, this->server->port);
				}
				this->peer_db.update(r);
				
				// send a peer list to the peer 
				string peers = peer_db.to_string(25);
				
				p->socket->sendCommand(CMD_PEER_LIST, peers.c_str(), peers.length());
	
				p->last_peer_list_submit = time(0);
			}
		}
		it++;
	}

	
	for(list<Peer*>::iterator it = peers.begin(); 
			it != peers.end();){
		Peer *p = (*it);
		if(p->socket->state & CON_STATE_DISCONNECTED){
			delete p;
			peers.erase(it++);
			continue;
		} 
		it++;
	}
	
	VSLNode *client = 0;
	if((client = (VSLNode*)this->server->accept())){
		cout << "[client] new connection: " << client->host << ":" << client->port << endl;
		PeerDatabase::Record r;
		r.peer = PeerAddress(client->host, 9000);
		r.hub = PeerAddress(server->host, server->port);
		peer_db.insert(r);
		
		Peer *peer = new Peer(client);
		//peer->setListener(new _PeerListener(this));
		peers.push_back(peer);
	}
}


LinkNode *Network::createCircuit(unsigned int length){
	stringstream ss;
	for(unsigned int c = 0;c<length;c++){
		ss<<"*";
		if(c!=length-1)
			ss<<">";	
	}
	
	LinkNode *link = this->createLink(ss.str());
	return link;
}

Network::~Network(){
	LOG("NET: shutting down..");
	
	// close connections
	for(list<Peer*>::iterator it = peers.begin(); it != peers.end(); it++){
		delete *it;
	}
	
	// use this function to release the UDT library
	UDT::cleanup();
}
