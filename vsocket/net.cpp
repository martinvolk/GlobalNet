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
	LOG("=================> USING PEER "<<r);
	if(!peers.size()) return 0;
	int c=0;
	for(PeerList::iterator it = peers.begin();
			it != peers.end(); it++){
		if(r == c) return (*it).second;
		c++;
	}
	return 0;
}
/**
Establish a link through the nodes specified in path. 
Path: [ip:port]>[ip:port]
**/

Node *Network::createLink(const string &path){
	vector<string> tokens;
	
	tokenize(path, ">", tokens);
	
	VSLNode *parent = connect(this->server->host.c_str(), this->server->port);
	
	LOG("NET: setting up tunnel: "<<path);
	
	// go through each step in the chain and establish appropriate connections through
	// all the intermediate hosts in the chain. They will all end up as ordinary peer connections to the user. 
	for(vector<string>::iterator it = tokens.begin(); it != tokens.end(); it++){
		vector<string> tmp;
		tokenize(*it, ":", tmp);
		string host, proto;
		int port = 9000;
		if(tmp.size() == 3){
			proto = tmp[0];
			host = tmp[1];
			port = atoi(tmp[2].c_str());
		} else if(tmp.size() == 2){
			proto = "peer";
			host = tmp[0];
			port = atoi(tmp[1].c_str());
		} else if(tmp[0] == "*"){
			// pick random host from already connected peers (in the future make it pick from "known peers")
			vector<PeerDatabase::Record> random = this->peer_db.random(1);
			if(!random.size()){
				ERROR("Link: could not create link! No peers connected!");
				return 0;
			}
			proto = "peer";
			host = random[0].peer.ip;
			port = random[0].peer.port;
		} else {
			ERROR("LINK: error parsing connect string!");
		}
		
		LOG("[link] establishing intermediate connection to "<<host<<":"<<port);
		
		// now we need to create a hash that we will send with relay connect to the first host
		stringstream ss;
		ss<<time(0)<<rand();
		SHA1Hash nodehash = SHA1Hash::compute(ss.str());
		ss.str("");
		ss<<nodehash.hex()<<":"<<proto<<":"<<host<<":"<<port;
			
		if(proto.compare("peer") == 0){
			// create the request
			parent->sendCommand(RELAY_CONNECT, ss.str().c_str(), ss.str().length());
		
			VSLNode *peer = new VSLNode(0);
			NodeAdapter *bridge = new NodeAdapter(peer);
			
			peer->connect(nodehash.hex().c_str(), 0);
			
			peers[nodehash.hex().c_str()] = peer;
			
			accept_table[nodehash.hex()] = pair<Node*, Node*>(bridge, parent);
			
			parent = peer;
			
			continue;
		} else if(proto.compare("tcp") == 0){
			MemoryNode *mem = new MemoryNode();
			NodeAdapter *bridge = new NodeAdapter(mem);
			
			parent->sendCommand(CMD_OUTBOUND_CONNECT, ss.str().c_str(), ss.str().length());
			
			accept_table[nodehash.hex()] = pair<Node*, Node*>(bridge, parent); 
			
			return mem;
		}
		break;
	}
	// return the last node that was created in the chain
	return parent;
}

// sets up a tunnel to the peer
Node * Network::createTunnel(const string &host, uint16_t port) {
	// create a tunnel through the network
	return this->createLink(string("*>*>tcp:")+host+":"+VSL::to_string(port));
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
	for(unsigned int c =0; c<ifs.size(); c++){
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
string con_state_to_string(int state);
// establish a new connection or set up a new connection within an existing one
VSLNode *Network::connect(const char *hostname, int port){
	PeerList::iterator it = peers.find(string(hostname)+":"+VSL::to_string(port));
	VSLNode *node = 0;
	if(it == peers.end()){
		LOG("NET: connecting to peer "<<hostname<<":"<<port);
		node = new VSLNode(0);
		node->connect(hostname, port);
		peers[string(hostname)+":"+VSL::to_string(port)] = node;
		
		PeerDatabase::Record r;
		r.peer.ip = inet_get_ip(hostname);
		r.peer.port = port;
		peer_db.insert(r);
		return node;
	}
	return (*it).second;
}

void Network::run() {
	//this->peer_db.purge();
	
	PeerDatabase::Record r;
	r.peer.ip = this->server->host;
	r.peer.port = this->server->port;
	peer_db.insert(r);
	
	// receive packets from peers and route them to where they should go
	for(PeerList::iterator it = peers.begin(); 
			it != peers.end(); ){
		Peer *p = (*it).second;
		Packet pack;
		
		// remove peers that have disconnected 
		if(p->state & CON_STATE_DISCONNECTED){
			//delete p;
			//peers.erase(it++);
			it++;
			continue;
		}
		p->run();
		if(p->state & CON_STATE_CONNECTED){
			if(p->recvCommand(&pack)){
				//LOG("NET: received command from "<<s->host<<":"<<s->port<<": "<<pack.cmd.code);
				if(pack.cmd.code == CMD_PEER_LIST){
					LOG("NET: received active peer list "<<string(pack.data)<<", "<<pack.size());
					
					peer_db.from_string(string(pack.data));
				} 
				// set up a new MEM >><< VSL configuration and link it to the ID hash 
				// always sets up a virtual vsl node on this host and relays messages to it tagged with hash
				if(pack.cmd.code == CMD_CONNECT){
					LOG("NET: CONNECT!");
					// data contains hash that will be used to send and receive data 
					string hash = pack.data;
					VSLNode *node = new VSLNode(SOCK_SERVER);
					//exit(0);
					NodeAdapter *bridge = new NodeAdapter(node); 	
					accept_table[hash] = pair<Node*, Node*>(bridge, p);
					peers[hash] = node;
				}
				// Establish a link from p to another connection node
				if(pack.cmd.code == CMD_OUTBOUND_CONNECT){
					LOG("NET: OUTBOUD_CONNECT");
					string str = string(pack.data);
					vector<string> tokens;
					tokenize(str, ":",tokens);
					string hash, proto, host;
					uint16_t port = 9000;
					if(tokens.size() == 3){
						hash = tokens[0];
						proto = tokens[1];
						host = tokens[2];
						port = atoi(tokens[3].c_str());
					} else {
						ERROR("NET: malformed relay packet. Should contain ID:PROTO:IP:PORT");
						continue; 
					}
					
					Node *peer = Node::createNode(proto.c_str());
					peer->connect(host.c_str(), port);
					
					accept_table[hash] = pair<Node*, Node*>(peer, p);
				}
				if(pack.cmd.code == RELAY_CONNECT){
					// data should contain a string of format ID:PEER_IP:PORT
					char tmp[SOCKET_BUF_SIZE];
					memcpy(tmp, pack.data, min((unsigned long)SOCKET_BUF_SIZE, (unsigned long)pack.cmd.size));
					tmp[pack.cmd.size] = 0;
					
					LOG("RELAY_CONNECT: "<<tmp);
					
					string str = string(tmp);
					vector<string> tokens;
					tokenize(str, ":",tokens);
					string hash, proto, host;
					uint16_t port = 9000;
					if(tokens.size() == 4){
						hash = tokens[0];
						proto = tokens[1];
						host = tokens[2];
						port = atoi(tokens[3].c_str());
					} else {
						ERROR("NET: malformed relay packet. Should contain ID:PROTO:IP:PORT");
						continue; 
					}
					
					VSLNode *peer = connect(host.c_str(), port);
					
					// make new hash 
					stringstream ss;
					ss<<time(0)<<rand();
					SHA1Hash nodehash = SHA1Hash::compute(ss.str());
					
					peer->sendCommand(CMD_CONNECT, nodehash.hex().c_str(), nodehash.hex().length());
					
					forward_table[hash] = pair<string, Node*>(nodehash.hex(), peer);
				}
				// handle data packets received from peers. 
				// Usually these should be forwarded to another node that will handle them . 
				if(pack.cmd.code == CMD_DATA){
					// lookup where the data should be sent
					LOG("NET: DATA from:["<<p->host<<":"<<p->port<<"] addressed to:"<<pack.cmd.hash.hex());
					SHA1Hash hash = pack.cmd.hash;
					// figure out what to do with it. 
					map<string, pair<Node*, Node*> >::iterator i = accept_table.find(hash.hex());
					if(i != accept_table.end()){
						(*i).second.first->send(pack.data, pack.cmd.size);
					}
					map<string, pair<string, Node*> >::iterator j = forward_table.find(hash.hex());
					if(j != forward_table.end()){
						// forward the data packet
						pack.cmd.hash.from_hex_string((*j).second.first);
						(*j).second.second->sendCommand(pack);
					}
				}
			} // recvCommand
		}
		it++;
	} // loop peers
	
	// read data from external connections and route it to the right peers
	for(map<string, pair<Node*, Node*> >::iterator it = accept_table.begin(); it != accept_table.end(); ){
		int rc; 
		char tmp[SOCKET_BUF_SIZE];
		Node *first = (*it).second.first;
		Node *second = (*it).second.second;
		
		if((rc = first->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG("NET: forwarding data "<<rc<<" bytes from accept queue to peer: "<<second->host);
			Packet pack; 
			pack.cmd.code = CMD_DATA;
			pack.cmd.hash.from_hex_string((*it).first);
			pack.cmd.size = rc;
			memcpy(pack.data, tmp, min(sizeof(pack.data), (unsigned long)rc));
			second->sendCommand(pack);
		}
		it++;
	}
	
	// send some commands if it is time. 
	if(this->last_peer_list_broadcast < time(0) - NET_PEER_LIST_INTERVAL){
		LOG(endl<<"CONNECTIONS:");
		for(map<string, pair<Node*, Node*> >::iterator it = accept_table.begin(); it != accept_table.end(); ){
			//LOG((*it)->host<<":"<<(*it)->port<<", state: "<<con_state_to_string((*it)->state));
			it++;
		}
		LOG("PEERS:");
		for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
			Peer *p = (*it).second;
			LOG(p->host<<":"<<p->port<<", state: "<<con_state_to_string(p->state));
		}
		for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
			//LOG("NET: sending peer list to the peer.");
			Peer *p = (*it).second;
			// update the record of the current peer in the database 
			PeerDatabase::Record r; 
			// we add the peer to the database if he has provided a listen address
			// the database will automatically check if it's valid later. 
			PeerAddress adr = PeerAddress(p->host, CLIENT_BIND_PORT);
			if(adr.is_valid()){
				r.peer = adr;
				this->peer_db.update(r);
			}
			else {
				// peer does not have a dedicated listening socket. 
				// we put the peer into database, but supply our own address as relay host
				r.hub = PeerAddress(this->server->host, this->server->port);
				this->peer_db.update(r);
			}
			
			// send a peer list to the peer 
			string peers = peer_db.to_string(25);
			p->sendCommand(CMD_PEER_LIST, peers.c_str(), peers.length());
		}
		this->last_peer_list_broadcast = time(0);
	}
	
	// accept incoming client connections on the standard port 
	VSLNode *client = 0;
	if(server && server->state & CON_STATE_LISTENING && (client = (VSLNode*)this->server->accept())){
		cout << "[client] new connection: " << client->host << ":" << client->port << endl;
		PeerDatabase::Record r;
		r.peer = PeerAddress(client->host, 9000);
		r.hub = PeerAddress(server->host, server->port);
		peer_db.insert(r);
		
		//peer->setListener(new _PeerListener(this));
		peers[client->host+":"+VSL::to_string(client->port)] = client;
	}
}

/*
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
*/
Network::~Network(){
	LOG("NET: shutting down..");
	
	// close connections
	for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
		delete (*it).second;
	}
	
	// use this function to release the UDT library
	UDT::cleanup();
}
