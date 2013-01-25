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

Network::Network(){
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings(); 
	OpenSSL_add_all_algorithms();
	
	// use this function to initialize the UDT library
	UDT::startup();
	
	this->server = new VSLNode();
	
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
		stringstream ss; 
		ss<<"vsl://"<<listen_adr<<":"<<port;
		if(this->server->listen(URL(ss.str()))){
			LOG("NET: peer listening on "<<this->server->url.url());
			break;
		}
		if(port == SERV_LISTEN_PORT + 1000){
			ERROR("ERROR no available listen ports left!");
		}
	}
	
	// blacklist our own address from local peer database to avoid localhost connections
	peer_db.blacklist(listen_adr);
}

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
Create a new tunnel to the url that is specified in the argument. 

The link will be created through the number of intermediate hosts 
specified with "length" paramenter. The returned node is a Channel 
node that can be used to communicate with the target url. 

Examples: 
- createTunnel("tcp://google.com:80", 3) > create a tunnel to 
google.com through three other intermediate relays. The returned link 
is the equivalent of a TCP socket connected directly to google.com. 
- createTunnel("vsl://10.10.0.2:9000", 3) > connect to another peer 
through three intermediates. The returned socket is an equivalent of a 
Channel established to the peer through a local connection. 

More complex examples: 
 Node *node = createTunnel("vsl://10.10.0.2:9000", 3);
 node->connect("tcp://google.com:80"); 
 
Creates a tunnel to 10.10.0.2 first and then instructs the tunnel to 
establish another connection to google.com. The connection will 
originate from 10.10.0.2. This can be used to make sure that 
google.com sees 10.10.0.2 as the source IP. 

 Node *node = createTunnel("tcp://google.com:80", 3);
 node->connect("tcp://yahoo.com:80"); 

Since the node that is returned in this case is a handle to a TCP 
connection, the subsequent call to connect to yahoo will close 
connection to google and connect to yahoo instead. 

**/

Node *Network::createTunnel(const URL &url, unsigned int length){
	vector<PeerDatabase::Record> random = this->peer_db.random(length);
	if(random.size() < length){
		ERROR("NET: NOT ENOUGH PEERS TO ESTABLISH CONNECTION OF LENGTH "<< 
		length);
	}
	if(!random.size()) return 0;
	
	LOG("NET: setting up tunnel to "<<url.url());
	
	LOG("NET: connecting to intermediate hop: "<<random[0].peer.url());
	// we connect directly to the first peer. 
	Node *parent = connect(random[0].peer);
	
	// and then through the first peer, we issue connection requests to 
	// subsequent peers. 
	for(unsigned int c = 1; c<random.size(); c++){
		// does a relay connect to the next peer. 
		parent->connect(random[c].peer);
		// put the remote channel into encryption mode and create a new 
		// encryption node that will encrypt all the traffic. 
		parent->sendCommand(CMD_ENCRYPT_BEGIN, "", 0, "");
		VSLNode *node = new VSLNode();
		node->set_output(parent);
		node->do_handshake(SOCK_CLIENT);
		registerPeer(node);
		
		Channel *chan = new Channel(node);
		channels[chan] = chan; 
		parent = chan;
	}
	// parent is now a channel established to the last node in the chain.
	// doing a connect on it for the last time will establish a 
	// connection to the final url. 
	LOG("NET: issuing remote connect to final hop: "<<url.url());
	
	parent->connect(url);
	return parent; 
}

string con_state_to_string(int state);

// establish a new connection to the url
Node *Network::connect(const URL &url){
	if(url.protocol().compare("vsl") == 0){
		PeerList::iterator it = peers.find(url.url());
		// if don't have a connection then we connect
		VSLNode *node = 0;
		if(it == peers.end()){
			LOG("NET: connecting to peer "<<url.url());
			node = new VSLNode();
			node->connect(url);
			peers[url.url()] = node;
			
			PeerDatabase::Record r;
			r.peer = url;
			peer_db.insert(r);
		}
		else {
			node = (*it).second;
		}
		Channel *chan = new Channel(node);
		channels[chan] = chan;
		return chan;
	}
	else if(url.protocol().compare("tcp") == 0){
		TCPNode *tcp = new TCPNode();
		tcp->connect(url);
		connections[tcp] = tcp;
		return tcp;
	}
	return 0;
}

void Network::run() {
	//this->peer_db.purge();
	
	PeerDatabase::Record r;
	r.peer = this->server->url;
	peer_db.insert(r);
	
	// accept incoming client connections on the standard port 
	VSLNode *client = 0;
	if(server && server->state & CON_STATE_LISTENING && (client = (VSLNode*)this->server->accept())){
		PeerDatabase::Record r;
		r.peer = client->url;
		r.hub = server->url;
		peer_db.insert(r);
		
		//peer->setListener(new _PeerListener(this));
		peers[client->url.url()] = client;
	}
	for(PeerList::iterator it = peers.begin(); 
			it != peers.end(); ){
		Peer *peer = (*it).second;
		Packet pack;
		
		peer->run();
		
		it++;
	}
	
	if(this->last_peer_list_broadcast < time(0) - NET_PEER_LIST_INTERVAL){
		LOG(endl<<"CONNECTIONS:");
		
		LOG("PEERS:");
		for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
			Peer *p = (*it).second;
			LOG(p->url.url()<<", state: "<<con_state_to_string(p->state));
		}
		for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
			//LOG("NET: sending peer list to the peer.");
			Peer *p = (*it).second;
			// update the record of the current peer in the database 
			PeerDatabase::Record r; 
			r.peer = p->url;
			this->peer_db.update(r);
			
			// send a peer list to the peer 
			string peers = peer_db.to_string(25);
			p->sendCommand(CMD_PEER_LIST, peers.c_str(), peers.length(), "");
		}
		this->last_peer_list_broadcast = time(0);
	}
	
	/*
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
					if(tokens.size() == 4){
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
					forward_table[nodehash.hex()] = pair<string, Node*>(hash, p);
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
					else {
						map<string, pair<string, Node*> >::iterator j = forward_table.find(hash.hex());
						if(j != forward_table.end()){
							// forward the data packet
							pack.cmd.hash.from_hex_string((*j).second.first);
							(*j).second.second->sendCommand(pack);
						}
						else {
							ERROR("NET: received data don't know what to do with it. addressed to:"<<pack.cmd.hash.hex());
						}
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
		
		first->run();
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
	
	*/
	
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


Node *Network::createNode(const string &name){
	if(name.compare("vsl")==0){
		return new VSLNode();
	}
	else if(name.compare("tcp")==0){
		return new TCPNode();
	}
	else if(name.compare("udt")==0){
		return new UDTNode();
	}
	else if(name.compare("ssl")==0){
		return new SSLNode();
	}
	else if(name.compare("socks")==0){
		return new SocksNode();
	}
	else{
		ERROR("Unknown socket type '"<<name<<"'");
	}
	return 0;
}

void Network::free(Node *node){
	//delete node;
}

Network::~Network(){
	LOG("NET: shutting down..");
	
	// close connections
	for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
		delete (*it).second;
	}
	
	// use this function to release the UDT library
	UDT::cleanup();
}
