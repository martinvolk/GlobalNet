/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
	
	
	// blacklist our own address from local peer database to avoid localhost connections
	//m_pPeerDb->blacklist(listen_adr);
}

void Network::init(){
	unique_ptr<UDTNode> udt(new UDTNode(shared_from_this()));
	unique_ptr<SSLNode> ssl(new SSLNode(shared_from_this(), move(udt), SOCK_SERVER));
	this->server = unique_ptr<VSLNode>(new VSLNode(shared_from_this(), move(ssl)));
	this->last_peer_list_broadcast = 0;
	
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
	
	m_pPeerDb = shared_ptr<PeerDatabase>(new PeerDatabase());
}

Network::~Network(){
	LOG(1,"NET: shutting down..");
	
	m_pPeerDb.reset();
	
	m_Bridges.clear();
	
	LOG(3,"NET: deleting channels..");
	m_Channels.clear();
	
	// close connections
	LOG(3,"NET: deleting peers..");
	for(map<string, shared_ptr<Node> >::iterator it = m_Peers.begin(); it != m_Peers.end();){
		LOG(3, "NET: deleting peer "<<(*it).first);
		(*it).second.reset();
		m_Peers.erase(it++);
	}
	m_Peers.clear();
	server.reset();
	
	
	LOG(3,"NET: cleaning up UDT..");
	// use this function to release the UDT library
	UDT::cleanup();
}
/*
VSLNode* Network::getRandomPeer(){
	int r = rand() % m_Peers.size();
	LOG(1,"=================> USING PEER "<<r);
	if(!m_Peers.size()) return shared_ptr<VSLNode>();
	int c=0;
	for(map<string, shared_ptr<Node> >::iterator it = m_Peers.begin();
			it != m_Peers.end(); it++){
		if(r == c) return (*it).second.get();
		c++;
	}
	return 0;
}
*/
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

unique_ptr<Node> Network::createTunnel(const list<URL> &links){
	list<URL>::const_iterator li = links.begin();
	if(!links.size()) return unique_ptr<Node>();
	
	LOG(1,"NET: connecting to intermediate hop: "<<(*li).url());
	// we connect directly to the first peer. 
	unique_ptr<Node> chan = this->connect(*li);
	li++;
	
	// and then we create new encryption nodes and connect them through
	// the first peer. 
	while(li != links.end()){
		// does a relay connect to the next peer. 
		LOG(2,"NET: sending RELAY_CONNECT to "<<chan->url.url()<<" adr: "<<chan.get());
		chan->sendCommand(Packet(RELAY_CONNECT, (*li).url().c_str(), (*li).url().length(), ""));
		
		// set up encryption if the relay is a VSL one. 
		if((*li).protocol().compare("vsl") == 0){
			// put the remote channel into encryption mode and create a new 
			// encryption node that will encrypt all the traffic. 
			LOG(2,"CHANNEL: sending ENCRYPT_BEGIN to "<<chan->url.url());
			chan->sendCommand(Packet(CMD_ENCRYPT_BEGIN, "", 0, ""));
			
			unique_ptr<SSLNode> ssl(new SSLNode(shared_from_this(), move(chan), SOCK_CLIENT));
			ssl->do_handshake();
			shared_ptr<VSLNode> node(new VSLNode(shared_from_this(), move(ssl)));
			//node->do_handshake(SOCK_CLIENT);
			
			// make new target a channel of the new node. 
			chan = node->createChannel();
			m_Peers[VSL::to_string(rand())] = node;
		}
		
		li++;
		
		// put the remote channel into encryption mode and create a new 
		// encryption node that will encrypt all the traffic. 
		/*LOG(1,"NET: sending ENCRYPT_BEGIN to "<<parent->url.url());
		parent->sendCommand(CMD_ENCRYPT_BEGIN, "", 0, "");
		
		VSLNode *node = new VSLNode(this);
		node->setOutput(parent);
		node->do_handshake(SOCK_CLIENT);
		peers[VSL::to_string(rand())] = node;
		
		Channel *chan = node->createChannel();
		//parent_node = node;
		parent = chan;*/
	}
	//if(parent_node) peers[full_path] = parent_node;
	return move(chan);
}

string con_state_to_string(int state);

// establish a new connection to the url
unique_ptr<Node> Network::connect(const URL &url){
	if(url.protocol().compare("vsl") == 0){
		map<string, shared_ptr<Node> >::iterator it = m_Peers.find(url.url());
		// if don't have a connection then we connect
		unique_ptr<Channel> chan;
		if(it == m_Peers.end()){
			LOG(1,"NET: connecting to peer "<<url.url());
			unique_ptr<UDTNode> udt(new UDTNode(shared_from_this()));
			unique_ptr<SSLNode> ssl(new SSLNode(shared_from_this(), move(udt), SOCK_CLIENT));
			shared_ptr<VSLNode> node(new VSLNode(shared_from_this(), move(ssl)));
			node->connect(url);
			chan = node->createChannel();
			m_Peers[url.url()] = node;
			
			PeerDatabase::Record r;
			r.peer = url;
			m_pPeerDb->insert(r);
		}
		else {
			LOG(3, "NET: using an already connected peer for "<<url.url());
			chan = dynamic_pointer_cast<VSLNode>((*it).second)->createChannel();
		}
		return move(chan);
	}
	else if(url.protocol().compare("tcp") == 0){
		unique_ptr<TCPNode> tcp(new TCPNode(shared_from_this()));
		tcp->connect(url);
		return move(tcp);
	}
	else if(url.protocol().compare("udt") == 0){
		unique_ptr<UDTNode> udt(new UDTNode(shared_from_this()));
		udt->connect(url);
		return move(udt);
	}
	else {
		ERROR("NET: connect: INVALID PROTOCOL: "<<url.protocol());
	}
	return unique_ptr<Node>();
}

void Network::run() {
	//this->m_pPeerDb->purge();
	
	if(this->server){
		PeerDatabase::Record r;
		r.peer = this->server->url;
		m_pPeerDb->insert(r);
	}
	
	// accept incoming client connections on the standard port 
	unique_ptr<Node> client;
	if(server && server->state & CON_STATE_LISTENING && (client = this->server->accept())){
		PeerDatabase::Record r;
		r.peer = client->url;
		r.hub = server->url;
		m_pPeerDb->insert(r);
		
		//peer->setListener(new _PeerListener(this));
		if(m_Peers.find(client->url.url()) != m_Peers.end()){
			ERROR("NET: run: trying to add a peer that already exists!!");
		}
		LOG(3, "NET: peer connected from "<<client->url.url());
		m_Peers[client->url.url()] = move(client);
	}
	
	// RUN ALL MANAGED CHANNELS
	for(list<unique_ptr<Channel> >::iterator it = m_Channels.begin();
			it != m_Channels.end(); ){
		Packet pack; 
		if((*it)->state & CON_STATE_DISCONNECTED){
			m_Channels.erase(it++);
			continue;
		}
		if((*it)->recvCommand(pack)){
			LOG(3, "NET: received command: "<<pack.cmd.code);
			if(pack.cmd.code == RELAY_CONNECT){
				LOG(3, "NET: RELAY_CONNECT from "<<(*it)->url.url());
				// create a bridge that will manage the channel for us from now on
				unique_ptr<Node> con = this->connect(URL(string(pack.data.begin(), pack.data.end())));
				if(con){
					// now we need to set up chan <- adapter -> con
					unique_ptr<BridgeNode> bridge(new BridgeNode(shared_from_this(), move(*it), move(con)));
					m_Bridges.push_back(move(bridge));
					m_Channels.erase(it++);
					continue;
				}
			}
			else if(pack.cmd.code == CMD_ENCRYPT_BEGIN){
				LOG(3, "NET: ENCRYPT_BEGIN from "<<(*it)->url.url());
				// here we create a new encrypted node and make it manage the channel
				// ssl will write into a buffer, buffer will be read by adapter and 
				// fed into our channel. VSL will be stored as a peer
				//shared_ptr<Buffer> buf(new Buffer());
				//unique_ptr<Node> transport(new MemoryNode(shared_from_this(), buf));
				// ssl will write into the current channel and read encrypted data from it. 
				unique_ptr<SSLNode> ssl(new SSLNode(shared_from_this(), move(*it), SOCK_SERVER));
				ssl->do_handshake();
				shared_ptr<VSLNode> node(new VSLNode(shared_from_this(), move(ssl)));
				node->url = URL("vsl://"+pack.cmd.hash.hex());
				
				m_Peers[node->url.url()] = node;
				
				// we can replace the current channel simply with the new layered one.
				//*it = move(node->createChannel(
				m_Channels.erase(it++);
				continue;
			}
			
		}
		it++;
	}
	
	for(list<unique_ptr<BridgeNode> >::iterator it = m_Bridges.begin();
			it != m_Bridges.end(); ){
		if((*it)->state & CON_STATE_DISCONNECTED){
			m_Bridges.erase(it++);
			continue;
		}
		(*it)->run();
		it++;
	}	
	
	//for(map<Channel*, Channel*>::iterator it = channels.begin();
	//	it != channels.end(); it++){
	//	(*it).second->run();
	//}
	
	// RUN ALL PEERS
	for(map<string, shared_ptr<Node> >::iterator it = m_Peers.begin(); 
			it != m_Peers.end(); ){
		Packet pack;
		if((*it).second->state & CON_STATE_DISCONNECTED){
			(*it).second.reset();
			m_Peers.erase(it++);
			//it++;
			continue;
		}
		(*it).second->run();
		
		it++;
	}
	
	// SEND PEER LISTS
	if(this->last_peer_list_broadcast < time(0) - NET_PEER_LIST_INTERVAL){
		LOG(1,endl<<"CONNECTIONS:");
		
		LOG(1,"PEERS:");
		for(map<string, shared_ptr<Node> >::iterator it = m_Peers.begin(); it != m_Peers.end(); it++){
			LOG(1,(*it).first<<", state: "<<con_state_to_string((*it).second->state));
		}
		for(map<string, shared_ptr<Node> >::iterator it = m_Peers.begin(); it != m_Peers.end(); it++){
			//LOG(1,"NET: sending peer list to the peer.");
			// update the record of the current peer in the database 
			PeerDatabase::Record r; 
			r.peer = (*it).second->url;
			this->m_pPeerDb->update(r);
			
			// send a peer list to the peer 
			string peers = m_pPeerDb->to_string(25);
			(*it).second->sendCommand(Packet(CMD_PEER_LIST, peers.c_str(), peers.length(), ""));
		}
		this->last_peer_list_broadcast = time(0);
	}
	
	
}

void Network::onChannelConnected(unique_ptr<Channel> chan){
	// if we don't want to manage the newly connected channel, 
	// we can just let it be and it will be destroyed because pointer
	// is a unique_ptr so we have the only copy. 
	LOG(3, "NET: new channel connected! "<<chan->id()<<" "<<chan.get()<<" from: "<<chan->url.url());
	m_Channels.push_back(move(chan));
}

shared_ptr<Node> Network::createNode(const string &name){
	if(name.compare("vsl")==0){
		//unique_ptr<Node> udt(new UDTNode(shared_from_this()));
		//unique_ptr<Node> ssl(new SSLNode(shared_from_this(), move(udt)));
		//return shared_ptr<Node>(new VSLNode(shared_from_this(), move(ssl)));
		return shared_ptr<Node>();
	}
	else if(name.compare("tcp")==0){
		return shared_ptr<Node>(new TCPNode(shared_from_this()));
	}
	else if(name.compare("udt")==0){
		return shared_ptr<Node>(new UDTNode(shared_from_this()));
	}
	//else if(name.compare("ssl")==0){
	//	return shared_ptr<Node>(new SSLNode(shared_from_this(), unique_ptr<Node>(new TCPNode(shared_from_this()))));
	//}
	else if(name.compare("socks")==0){
		return shared_ptr<Node>(new SocksNode(shared_from_this()));
	}
	else{
		ERROR("Unknown socket type '"<<name<<"'");
	}
	return shared_ptr<Node>();
}

void Network::free(Node *node){
	
}

