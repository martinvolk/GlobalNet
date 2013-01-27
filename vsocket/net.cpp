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
	
	this->server = new VSLNode(this);
	
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
			LOG(1,"NET: peer listening on "<<this->server->url.url());
			break;
		}
		if(port == SERV_LISTEN_PORT + 1000){
			ERROR("ERROR no available listen ports left!");
		}
	}
	
	// blacklist our own address from local peer database to avoid localhost connections
	//peer_db.blacklist(listen_adr);
}

Peer *Network::getRandomPeer(){
	int r = rand() % peers.size();
	LOG(1,"=================> USING PEER "<<r);
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

Node *Network::createTunnel(const list<URL> &links){
	/*vector<PeerDatabase::Record> random = this->peer_db.random(length);
	if(random.size() && random.size() < length){
		ERROR("NET: NOT ENOUGH PEERS TO ESTABLISH CONNECTION OF LENGTH "<< 
		length);
		// pad for testing..
		while(random.size()<length) random.push_back(random[0]);
	}
	if(!random.size()) return 0;
	
	LOG(1,"NET: setting up tunnel to "<<url.url());
	*/
	list<URL>::const_iterator li = links.begin();
	if(!links.size()) return 0;
	
	// see if we already have the vsl channel established through these 
	// peers. 
	/*string full_path;
	list<URL>::const_iterator i = links.begin();
	while(i != links.end()){
		if((*i).protocol().compare("vsl") != 0) break;
		if(full_path.length() != 0) full_path += ">";
		full_path += (*i).url();
		i++;
	}
	map<string, VSLNode*>::iterator it = peers.find(full_path);
	if(it != peers.end()){
		LOG(1,"NET: using existing link: "<<full_path);
		Channel *chan = new Channel(this, (*it).second);
		chan->connect(*i); // connect to the next node
		return chan;
	}*/
	
	LOG(1,"NET: connecting to intermediate hop: "<<(*li).url());
	// we connect directly to the first peer. 
	Node *parent = connect(*li);
	//VSLNode *parent_node = 0;
	li++;
	
	// and then through the first peer, we issue connection requests to 
	// subsequent peers. 
	for(unsigned int c = 0; c<links.size()-1; c++){
		// does a relay connect to the next peer. 
		
		LOG(1,"NET: connecting to intermediate hop: "<<(*li).url());
		
		// relay to the next host
		parent->connect(*li);
		
		li++;
		
		// put the remote channel into encryption mode and create a new 
		// encryption node that will encrypt all the traffic. 
		/*LOG(1,"NET: sending ENCRYPT_BEGIN to "<<parent->url.url());
		parent->sendCommand(CMD_ENCRYPT_BEGIN, "", 0, "");
		
		VSLNode *node = new VSLNode(this);
		node->set_output(parent);
		node->do_handshake(SOCK_CLIENT);
		peers[VSL::to_string(rand())] = node;
		
		Channel *chan = node->createChannel();
		//parent_node = node;
		parent = chan;*/
	}
	//if(parent_node) peers[full_path] = parent_node;
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
			LOG(1,"NET: connecting to peer "<<url.url());
			node = new VSLNode(this);
			node->connect(url);
			peers[url.url()] = node;
			
			PeerDatabase::Record r;
			r.peer = url;
			peer_db.insert(r);
		}
		else {
			node = (*it).second;
		}
		return node->createChannel();
	}
	else if(url.protocol().compare("tcp") == 0){
		TCPNode *tcp = new TCPNode(this);
		tcp->connect(url);
		return tcp;
	}
	else {
		ERROR("NET: connect: INVALID PROTOCOL: "<<url.protocol());
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
	
	//for(map<Channel*, Channel*>::iterator it = channels.begin();
	//	it != channels.end(); it++){
	//	(*it).second->run();
	//}
	
	for(PeerList::iterator it = peers.begin(); 
			it != peers.end(); ){
		Peer *peer = (*it).second;
		Packet pack;
		if(peer->state & CON_STATE_DISCONNECTED){
			//peers.erase(it++);
			//delete peer;
			//it++;
			//continue;
		}
		peer->run();
		
		it++;
	}
	
	if(this->last_peer_list_broadcast < time(0) - NET_PEER_LIST_INTERVAL){
		LOG(1,endl<<"CONNECTIONS:");
		
		LOG(1,"PEERS:");
		for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
			Peer *p = (*it).second;
			LOG(1,(*it).first<<", state: "<<con_state_to_string(p->state));
		}
		for(PeerList::iterator it = peers.begin(); it != peers.end(); it++){
			//LOG(1,"NET: sending peer list to the peer.");
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
	
	
}


Node *Network::createNode(const string &name){
	if(name.compare("vsl")==0){
		return new VSLNode(this);
	}
	else if(name.compare("tcp")==0){
		return new TCPNode(this);
	}
	else if(name.compare("udt")==0){
		return new UDTNode(this);
	}
	else if(name.compare("ssl")==0){
		return new SSLNode(this);
	}
	else if(name.compare("socks")==0){
		return new SocksNode(this);
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
	LOG(1,"NET: shutting down..");
	
	// close connections
	for(PeerList::iterator it = peers.begin(); it != peers.end();){
		delete (*it).second;
		peers.erase(it++);
	}
	
	// use this function to release the UDT library
	UDT::cleanup();
}
