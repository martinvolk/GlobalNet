/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"

/**
Establishes a channel on the VSLNode "link" and uses hash as the 
identifier for the new channel. 
\param net network that the channel node is part of
\param link the underlying VSL connection that the channel will be 
part of. 
\param hash the hash identifying the new channel (must be unique 
within the connection). 

If the hash is not set (or set to "") this function will create a new 
random hash and use that instead. The default value for the hash is in 
fact "" because normally you will want the Channel class to create a 
random hash. The hash parameter is only used on the server side where 
we get a hash sent to us by the other side and we have to use that 
hash speciffically for all communication. 

Dependencies: 
Channel keeps a pointer to VSLNode
VSLNode keeps a pointer to channel in it's list of listeners. 

When underlying VSLNode is destroyed, the channel becomes invalid. So 
should be destroyed as well. We don't delete the channel though 
because there can be pointers to it elsewhere. Just set it's state to 
disconnected and let the code that has set it up in the first place 
take care of the rest. 
**/
Channel::Channel(Network *net, VSLNode *link, const string &hash):Node(net),
	m_pRelay(0), m_pLink(link){
	
	if(!hash.length()){
		stringstream ss;
		ss<<time(0)<<rand();
		Packet p;
		p.cmd.code = CMD_CHAN_INIT;
		p.cmd.hash = SHA1Hash::compute(ss.str());
		m_sHash = p.cmd.hash.hex();
		LOG("CHANNEL: setting up new channel with "<<m_pLink->url.url());
		m_pLink->sendCommand(p);
	} else {
		m_sHash = hash;
	}
	state = CON_STATE_ESTABLISHED; 
	m_pLink->registerChannel(m_sHash, this);
}

/**
Destroys the Channel object. Does not delete "link". 
**/
Channel::~Channel(){
	state = 0;
	this->close();
	m_pLink->removeChannel(m_sHash);
}

/** 
Sends a close message to the remote end and closes the channel
**/
void Channel::close(){
	LOG("CHANNEL: closing channel "<<m_sHash);
	for(map<string, VSLNode*>::iterator it = m_Peers.begin(); 
			it != m_Peers.end(); ){
		//delete (*it).second;
		m_Peers.erase(it++);
	}
	//if(m_pRelay) delete m_pRelay;
	m_pRelay = 0;
	state = CON_STATE_DISCONNECTED;
}
	
/** 
A packet handler callback that is called by the underlying VSL 
connection when a new packet arrives addressed to this channel. 
Addressing is done with the random hash that is generated when a 
channel is set up. 
**/
void Channel::handlePacket(const Packet &pack){
	if(m_pRelay){
		m_pRelay->sendCommand(pack);
		return;
	}
	
	if(pack.cmd.code == RELAY_CONNECT_OK){
		state = CON_STATE_ESTABLISHED; 
	}
	else if(pack.cmd.code == CMD_CHAN_INIT){
		LOG("CHANNEL: received CHAN_INIT "<<pack.cmd.hash.hex()<<" from "<<url.url());
	}
	else if(pack.cmd.code == CMD_CHAN_CLOSE){
		close();
	}
	else if(pack.cmd.code == CMD_DATA){
		LOG("CHANNEL: DATA from "<<m_pLink->url.url()<<": "<<pack.cmd.size<<" bytes.");
		BIO_write(read_buf, pack.data, pack.cmd.size);
	}
	else if(pack.cmd.code == CMD_ENCRYPT_BEGIN){
		LOG("CHANNEL "<<m_sHash<<": ENCRYPT_BEGIN from "<<m_pLink->url.url());
		VSLNode *node = new VSLNode(m_pNetwork);
		node->url = URL("vsl://"+m_sHash);
		m_Peers[node->url.url()] = node;
		
		m_pRelay = new NodeAdapter(m_pNetwork, node);
		
		node->do_handshake(SOCK_SERVER);
	}
	
	else if(pack.cmd.code == RELAY_CONNECT){
		URL url = URL(pack.data);
		LOG("CHANNEL: "<<m_sHash<<" got relay connect from "<<m_pLink->url.url()<<": "<<url.url());
		// this will either return an existing connection or establish a new one
		m_pRelay = m_pNetwork->connect(url);
	}
}

/**
Initiates a realy connection on the remote end of the channel. 
\param url the url to connect to (ex. vsl://nodeip:port)
Subsequent calls close the previous remote connection and establish a 
new one. If the url specifies an address that the remote end is 
already connected to then a new channel is established on the existing 
connection. See documentation for handlePacket() for code that is run 
on the remote end of the channel. 
**/
int Channel::connect(const URL &url){
	Packet pack;
	pack.cmd.code = RELAY_CONNECT;
	pack.cmd.hash.from_hex_string(m_sHash);
	pack.cmd.size = url.url().length();
	memcpy(pack.data, url.url().c_str(), url.url().length());
	return m_pLink->sendCommand(pack);
}

/**
Calls link->sendCommand() 
**/
int Channel::sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag){
	return m_pLink->sendCommand(cmd, data, size, m_sHash);
}
/**
Sends \param data wrapped into a CMD_DATA packet to the link. 
**/
int Channel::send(const char *data, size_t maxsize, size_t minsize){
	return m_pLink->sendCommand(CMD_DATA, data, maxsize, m_sHash);
}

/**
Reads maxsize bytes from the internal buffer (inside Channel) that is 
filled inside handlePacket when a data packet is received. 
**/
int Channel::recv(char *data, size_t maxsize, size_t minsize){
	// disable reading for a relayed connection because everything will 
	// be passed to the relayed connection instead. 
	if(m_pRelay) return 0; 
	if(BIO_ctrl_pending(this->read_buf) < minsize || BIO_ctrl_pending(this->read_buf) == 0) return 0;
	int rc = BIO_read(read_buf, data, maxsize);
	if(rc > 0) LOG("CHANNEL: recv "<<rc<<" bytes.");
	return rc;
}

int Channel::listen(const URL &url){
	ERROR("CHANNEL LISTEN NOT IMPLEMENTED!");
	return -1;
}

Node* Channel::accept(){
	return 0;
}

/**
Copies data to and from the relay node
**/
void Channel::run(){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	if(m_bProcessingMainLoop) return;
	SETFLAG(m_bProcessingMainLoop, 0);
	
	if(this->_output)
		this->_output->run();
	
	m_pLink->run();
	this->url = m_pLink->url;
	
	// run all the nested connections on this channel
	for(map<string, VSLNode*>::iterator it = m_Peers.begin(); 
			it != m_Peers.end(); ){
		(*it).second->run();
		if((*it).second->state & CON_STATE_DISCONNECTED){
			//delete (*it).second;
			//m_Peers.erase(it++);
			//continue;
		}
		it++;
	}
	
	// shuffle data between us and the relay. 
	if(m_pRelay){// read data from one end and forward it to the other end and vice versa
		m_pRelay->run();
		
		if ((rc = m_pRelay->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG("CHANNEL: read "<<rc<<" bytes from relayed connection..");
			this->send(tmp, rc);
		}
		if(BIO_ctrl_pending(read_buf)>0){
			if((rc = BIO_read(read_buf, tmp, SOCKET_BUF_SIZE))>0){
				LOG("CHANNEL: write "<<rc<<" bytes to relayed connection..");
				m_pRelay->send(tmp, rc);
			}
		}
		//if(m_pRelay->state & CON_STATE_DISCONNECTED)
		//	close();
	}
}

