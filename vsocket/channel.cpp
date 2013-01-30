#include "local.h"

Channel::Channel(weak_ptr<Network> net, weak_ptr<VSLNode> link, const string &hash):Node(net),
	m_extLink(link){
	
	if(!hash.length()){
		stringstream ss;
		ss<<time(0)<<rand();
		Packet p;
		p.cmd.code = CMD_CHAN_INIT;
		p.cmd.hash = SHA1Hash::compute(ss.str());
		m_sHash = p.cmd.hash.hex();
		
		shared_ptr<VSLNode> tmp = link.lock();
		if(tmp){
			LOG(1,"CHANNEL: sending CHAN_INIT "<<m_sHash<<" to "<<tmp->url.url());
			tmp->sendCommand(p);
		}
	} else {
		m_sHash = hash;
	}
	m_pTarget.reset();
	m_bDeleteInProgress = false;
	state = CON_STATE_ESTABLISHED; 
	url = URL("vsl", m_sHash, 0);
}

/**
Unregisters the channel from the underlying VSLNode and sends 
disconnect to the remote end of the channel. 
**/
Channel::~Channel(){
	m_bDeleteInProgress = true;
	this->close();
	LOG(3, "CHANNEL: deleted "<<m_sHash);
}

void Channel::close(){
	LOG(3, "CHANNEL: cleaning up! "<<m_sHash); 	
	
	// relay is always created here. 
	m_pRelay.reset();
	m_pTarget.reset();
	
	// now delete the nodes
	for(list<shared_ptr<VSLNode> >::iterator it = m_Peers.begin(); 
			it != m_Peers.end(); it++){
		(*it).reset();
	}
	m_Peers.clear();
	m_Targets.clear();
	
	state = CON_STATE_DISCONNECTED;

	shared_ptr<VSLNode> link = m_extLink.lock();
	if(link){
		link->sendCommand(CMD_CHAN_CLOSE, "", 0, m_sHash);
		link->releaseChannel(m_sHash);
	}
}

void Channel::handlePacket(const Packet &pack){
	// forward the packet to relay if we have a relay connection
	if(m_pRelay){
		if(pack.cmd.code == CMD_DATA){
			LOG(2,"CHANNEL: Forwarding DATA to relay "<<m_pRelay->url.url()<<": "<<pack.cmd.size<<" bytes.");
			m_pRelay->send(pack.data.data(), pack.cmd.size);
		}
		else {
			LOG(2,"CHANNEL: Forwarding COMMAND to relay "<<m_pRelay->url.url());
			m_pRelay->sendCommand(pack);
		}
		return;
	}
	
	// otherwise we handle the packet internally.. :) 
	if(pack.cmd.code == CMD_CHAN_ACK || pack.cmd.code == RELAY_ACK){
		state = CON_STATE_ESTABLISHED; 
	}
	else if(state & CON_STATE_CONNECTED){
		if(pack.cmd.code == CMD_CHAN_CLOSE){
			state = CON_STATE_DISCONNECTED;
			close();
		}
		else if(pack.cmd.code == CMD_CHAN_INIT){
			LOG(2,"CHANNEL: received CHAN_INIT "<<pack.cmd.hash.hex()<<" from "<<url.url());
		}
		else if(pack.cmd.code == CMD_DATA){
			LOG(2,"CHANNEL: DATA at "<<url.url()<<", "
					<<pack.cmd.hash.hex()<<": "<<pack.cmd.size<<" bytes.");
			m_ReadBuffer.sendOutput(pack.data.data(), pack.data.size());
			//BIO_write(read_buf, pack.data, pack.cmd.size);
		}
		else if(pack.cmd.code == CMD_ENCRYPT_BEGIN){
			LOG(2,"CHANNEL: ENCRYPT_BEGIN at "<<url.url());
			
			// set up a encryptor chain and set relay to it's output and add node to the list of peers. 
			// it may look a little messy, but the memory node interfaces with a shared buffer 
			// that is also passed to node adapter so that we can write to it as though it was
			// and ordinary node. 
			shared_ptr<Buffer> buf(new Buffer());
			unique_ptr<Node> transport(new MemoryNode(m_pNetwork, buf));
			unique_ptr<SSLNode> ssl(new SSLNode(m_pNetwork, move(transport), SOCK_SERVER));
			shared_ptr<VSLNode> node(new VSLNode(m_pNetwork, move(ssl)));
			node->url = URL("vsl://"+m_sHash);
			
			m_pRelay = unique_ptr<NodeAdapter>(new NodeAdapter(m_pNetwork, buf));
			
			node->do_handshake(SOCK_SERVER);

			m_Peers.push_back(node);
		}
		
		else if(pack.cmd.code == RELAY_CONNECT){
			URL url = URL(pack.data.data());
			LOG(2,"CHANNEL: got RELAY_CONNECT at "<<url.url()<<": "<<url.url());
			// this will either return an existing connection or establish a new one
			// the returned pointer is a channel and so can be deleted later. 
			m_pRelay = m_pNetwork.lock()->connect(url);
			if(!m_pRelay){
				ERROR("CHANNEL: could not connect to "<<url.url());
				return;
			}
			this->sendCommand(RELAY_ACK, "", 0, m_sHash);
		}
		else if(pack.cmd.code == CMD_CHAN_CLOSE){
			close();
		}
		else {
			LOG(2, "CHANNEL: discarding unhandled command "<<pack.cmd.code);
		}
	}
	else {
		LOG(2, "CHANNEL: discarding unhandled command "<<pack.cmd.code);
	}
}

int Channel::connect(const URL &url){
	Packet pack;
	
	if(state & CON_STATE_DISCONNECTED)
		return -1;
		
	// create a parallel channel and close ourselves. 
	shared_ptr<VSLNode> link = m_extLink.lock();
	if(!link) return 0;
	
	if(!m_pTarget){
		m_pTarget = link->createChannel();
		link->releaseChannel(m_sHash);
	}
	
	
	LOG(2,"CHANNEL: sending RELAY_CONNECT to "<<m_pTarget->url.url());
	pack.cmd.code = RELAY_CONNECT;
	pack.cmd.hash.from_hex_string(m_sHash);
	pack.cmd.size = url.url().length();
	pack.data.reserve(url.url().length());
	memcpy(&pack.data[0], url.url().c_str(), url.url().length());
	m_pTarget->sendCommand(pack);
	
	if(url.protocol().compare("vsl") == 0){
		// put the remote channel into encryption mode and create a new 
		// encryption node that will encrypt all the traffic. 
		LOG(2,"CHANNEL: sending ENCRYPT_BEGIN to "<<m_pTarget->url.url());
		m_pTarget->sendCommand(CMD_ENCRYPT_BEGIN, "", 0, "");
		
		unique_ptr<SSLNode> ssl(new SSLNode(m_pNetwork, move(m_pTarget), SOCK_CLIENT));
		shared_ptr<VSLNode> node(new VSLNode(m_pNetwork, move(ssl)));
		node->do_handshake(SOCK_CLIENT);
		m_Peers.push_back(node);
		
		// make new target a channel of the new node. 
		m_pTarget = node->createChannel();
	}
	
	return 1;
}

int Channel::sendCommand(const Packet &pack){
	Packet p = pack;
	p.cmd.hash.from_hex_string(m_sHash);
	shared_ptr<VSLNode> link = m_extLink.lock();
	if(m_pTarget)
		return m_pTarget->sendCommand(p);
	if(link)
		link->sendCommand(p);
	return 0;
}
int Channel::sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag){
	LOG(3,"CHANNEL: sendCommand: "<<cmd<<", "<<hexencode(data, size)<<": "
			<<size<<" bytes.");
	shared_ptr<VSLNode> link = m_extLink.lock();
	if(m_pTarget)
		return m_pTarget->sendCommand(cmd, data, size, m_sHash);
	if(link)
		link->sendCommand(cmd, data, size, m_sHash);
	return 0;
}
int Channel::send(const char *data, size_t maxsize){
	shared_ptr<VSLNode> link = m_extLink.lock();
	if(m_pTarget)
		return m_pTarget->sendCommand(CMD_DATA, data, maxsize, m_sHash);
	if(link)
		link->sendCommand(CMD_DATA, data, maxsize, m_sHash);
	return 0;
}

int Channel::recv(char *data, size_t maxsize, size_t minsize) const{
	if(m_pRelay) return 0; // disable reading for a relayed connection
	if(m_pTarget) return m_pTarget->recv(data, maxsize, minsize);
	/*if(BIO_ctrl_pending(this->read_buf) < minsize || BIO_ctrl_pending(this->read_buf) == 0) return 0;
	int rc = BIO_read(read_buf, data, maxsize);*/
	//if(rc > 0) LOG(3,"CHANNEL: recv "<<rc<<" bytes.");
	return 0;
}

int Channel::listen(const URL &url){
	ERROR("CHANNEL LISTEN NOT IMPLEMENTED!");
	return -1;
}

unique_ptr<Node> Channel::accept(){
	return unique_ptr<Node>();
}

void Channel::run(){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	if(m_pTarget)
		m_pTarget->run(); 
	
	for(list<shared_ptr<VSLNode> >::iterator it = m_Peers.begin();
		it != m_Peers.end(); it++){
		(*it)->run();
	}
	if(m_pRelay && state & CON_STATE_CONNECTED){
		// shuffle data between us and the relay. 
		m_pRelay->run();
			
		if ((rc = m_pRelay->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG(3,"CHANNEL: read "<<rc<<" bytes from relayed connection..");
			this->send(tmp, rc);
		}
	}
	
	if((m_pRelay && m_pRelay->state & CON_STATE_DISCONNECTED) ||
		(m_pTarget && m_pTarget->state & CON_STATE_DISCONNECTED)){
		LOG(3,"CHANNEL: closing channel "<<m_sHash<<": relay disconnected!");
		close();
		return;
	}
}

	
