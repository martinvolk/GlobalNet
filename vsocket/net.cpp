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
Peer *Network::getRandomPeer(){
	int r = rand() % peers.size();
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
			Peer *peer = this->getRandomPeer();
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
	
	// attempt to find an available listen port. 1000 alternatives should be enough
	for(int port = SERV_LISTEN_PORT; port <= SERV_LISTEN_PORT + 1000; port ++){
		if(this->server->listen("localhost", port)){
			LOG("NET: peer listening on "<<this->server->host<<":"<<this->server->port);
			break;
		}
		if(port == SERV_LISTEN_PORT + 1000){
			ERROR("ERROR no available listen ports left!");
		}
	}
}

/*
VSLNode *Network::connect(const char *hostname, int port){
	Connection *conn = NET_allocConnection(self);
	Peer *peer = NET_allocPeer(self);
	
	// set up a new relay connection to the host
	CON_initPeer(*conn);
	conn->connect(*conn, hostname, port);
	peer->socket = conn;
	
	return conn;
}
*/
void Network::_handle_command(Node *source, const Packet &pack){
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
			PeerDatabase::Record r; 
			r.hub_ip = parts[0];
			r.hub_port = atoi(parts[1].c_str());
			r.peer_ip = parts[2];
			r.peer_port = atoi(parts[3].c_str()); 
			r.last_update = time(0) - packet_time + atol(parts[4].c_str());
			this->peer_db.insert(r);
			LOG(r.hub_ip<<":"<<r.hub_port<<";"<<r.peer_ip<<":"<<r.peer_port);
		}
	} 
}

void Network::run() {
	// send / recv data from all connections
	for(uint c=0;c<this->sockets.size(); c++){
		this->sockets[c]->run();
	}
	
	//this->peer_db.purge();
	
	// update our listen record
	PeerDatabase::Record r; 	
	r.hub_ip = "";
	r.hub_port = 0;
	r.peer_ip = this->server->host;
	r.peer_port = this->server->port;
	r.is_local = false;
	r.last_update = time(0);
	
	this->peer_db.insert(r);
				
	// monitor peers for replies
	for(list<Peer*>::iterator it = peers.begin(); 
			it != peers.end(); it++){
		Peer *p = (*it);
		Node *s = p->socket;
		Packet pack;
		if(s && s->state & CON_STATE_CONNECTED){
			if(s->recvCommand(&pack)){
				//LOG("NET: received command from "<<s->host<<":"<<s->port<<": "<<pack.cmd.code);
				this->_handle_command(s, pack);
			}
			// send some commands if it is time. 
			if(p->last_peer_list_submit < time(0) - NET_PEER_LIST_INTERVAL){
				// update the last_update times since we are still connected to this peer. 
				bool peer_ip_is_local = inet_ip_is_local(p->socket->host);
				bool peer_listen_address_is_peer_address = true;
				bool our_listen_ip_is_local = inet_ip_is_local(this->server->host);
				PeerDatabase::Record r; 
				
				r.hub_ip = this->server->host;
				r.hub_port = this->server->port;
				r.peer_ip = p->socket->host;
				r.peer_port = p->socket->port;
				r.is_local = peer_ip_is_local;
				r.last_update = time(0);
				
				if(r.peer_ip.compare("") != 0)
					this->peer_db.insert(r);
				
				// send a peer list to the peer 
				vector<PeerDatabase::Record> rand_set = this->peer_db.random(25);
				
				stringstream ss;
				ss<<time(0);
				for(size_t c=0;c< rand_set.size();c++){
					ss<<";"<<rand_set[c].hub_ip<<":"
						<<rand_set[c].hub_port<<":" 
						<<rand_set[c].peer_ip<<":"
						<<rand_set[c].peer_port<<":"
						<<rand_set[c].last_update;
				}
				LOG(ss.str());
				p->socket->sendCommand(CMD_PEER_LIST, ss.str().c_str(), ss.str().length());
	
				p->last_peer_list_submit = time(0);
			}
		}
	}

	
	// cleanup all unused objects
	for(uint c=0;c<sockets.size(); c++){
		if(this->sockets[c]->state & CON_STATE_DISCONNECTED)
			delete this->sockets[c];
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
		Peer *peer = new Peer(client);
		peer->socket = client;
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
	// close connections
	/*
	for(uint c=0;c<ARRSIZE(this->sockets); c++){
		if(this->sockets[c].initialized)
			CON_shutdown(this->sockets[c]);
	}
	*/
	// use this function to release the UDT library
	UDT::cleanup();
}
