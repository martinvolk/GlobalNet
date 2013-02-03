#include "local.h"

Channel::Channel(weak_ptr<Network> net, VSLNode* link, const string &hash):Node(net),
	m_extLink(link){
	
	if(!hash.length()){
		stringstream ss;
		ss<<time(0)<<rand();
		Packet p;
		p.cmd.code = CMD_CHAN_INIT;
		p.cmd.hash = SHA1Hash::compute(ss.str());
		m_sHash = p.cmd.hash.hex();
		
		//shared_ptr<VSLNode> tmp = link.lock();
		if(m_extLink){
			LOG(1,"CHANNEL: sending CHAN_INIT "<<m_sHash<<" to "<<m_extLink->url.url());
			m_extLink->sendCommand(p);
		}
	} else {
		m_sHash = hash;
	}
	//m_pTarget.reset();
	m_bDeleteInProgress = false;
	
	// signal other side that we are connected
	sendCommand(Packet(CMD_CHAN_ACK, "", 0, m_sHash));
	
	state = CON_STATE_ESTABLISHED; 
	url = URL("vsl", m_sHash, 0);
}

/**
Unregisters the channel from the underlying VSLNode and sends 
disconnect to the remote end of the channel. 
**/
Channel::~Channel(){
	LOG(3, "CHANNEL: deleting! "<<m_sHash);
	m_bDeleteInProgress = true;
	this->close();
}

void Channel::detach(){
	m_extLink = 0;
	close();
}
void Channel::close(){
	LOG(3, "CHANNEL: cleaning up! "<<m_sHash); 	
	
	// relay is always created here. 
	/*m_pRelay.reset();
	m_pTarget.reset();
	
	// now delete the nodes
	for(list<shared_ptr<VSLNode> >::iterator it = m_Peers.begin(); 
			it != m_Peers.end(); it++){
		(*it).reset();
	}
	m_Peers.clear();
	m_Targets.clear();
	*/
	state = CON_STATE_DISCONNECTED;

	if(m_extLink){
		m_extLink->sendCommand(CMD_CHAN_CLOSE, "", 0, m_sHash);
		m_extLink->releaseChannel(m_sHash);
	}
}

void Channel::handlePacket(const Packet &pack){
	// forward the packet to relay if we have a relay connection
	/*if(m_pRelay){
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
	*/
	// otherwise we handle the packet internally.. :) 
	if(pack.cmd.code == CMD_CHAN_ACK || pack.cmd.code == RELAY_ACK){
		state = CON_STATE_ESTABLISHED; 
	}
	else if(state & CON_STATE_CONNECTED){
		if(pack.cmd.code == CMD_DATA){
			LOG(2,"CHANNEL: DATA at "<<url.url()<<", "
					<<pack.cmd.hash.hex()<<": "<<pack.data.size()<<" bytes: "<<hexencode(pack.data.data(), pack.data.size()));
			m_ReadBuffer.sendOutput(pack.data.data(), pack.data.size());
			//BIO_write(read_buf, pack.data, pack.cmd.size);
		}
		else if(pack.cmd.code == CMD_CHAN_CLOSE){
			LOG(3, "CHANNEL: got CMD_CHAN_CLOSE! Channel: "<<m_sHash);
			close();
		}
		else {
			m_CommandBuffer.push_back(pack);
			LOG(3, "CHANNEL: storing unhandled command "<<this<<" "<<pack.cmd.code<<" from: "<<m_extLink->url.url()<<" "<<m_sHash<<" "<<
				hexencode(pack.data.data(), pack.data.size()));
		}
	}
	else {
		LOG(2, "CHANNEL: discarding unhandled command "<<pack.cmd.code);
	}
}

int Channel::connect(const URL &url){
	ERROR("CHANNEL: connect not implemented!");
	return -1;
}

int Channel::sendCommand(const Packet &pack){
	Packet p = pack;
	p.cmd.hash.from_hex_string(m_sHash);
	//shared_ptr<VSLNode> link = m_extLink.lock();
	//if(m_pTarget)
	//	return m_pTarget->sendCommand(p);
	if(m_extLink)
		m_extLink->sendCommand(p);
	return 0;
}

bool Channel::recvCommand(Packet &pack){
	if(!m_CommandBuffer.size()) return false;
	LOG(3, "CHANNEL: recvCommand: copying command to pack!");
	pack = m_CommandBuffer.front();
	m_CommandBuffer.pop_front();
	return true;
}

int Channel::sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag){
	LOG(3,"CHANNEL: sendCommand: "<<cmd<<", "<<hexencode(data, size)<<": "
			<<size<<" bytes.");
	//shared_ptr<VSLNode> link = m_extLink.lock();
	//if(m_pTarget)
	//	return m_pTarget->sendCommand(cmd, data, size, m_sHash);
	if(m_extLink)
		m_extLink->sendCommand(cmd, data, size, m_sHash);
	return 0;
}
int Channel::send(const char *data, size_t size){
	//shared_ptr<VSLNode> link = m_extLink.lock();
	LOG(3,"CHANNEL: send: "<<size<<" bytes.");
	//if(m_pTarget)
	//	return m_pTarget->sendCommand(CMD_DATA, data, size, m_sHash);
	if(m_extLink)
		m_extLink->sendCommand(CMD_DATA, data, size, m_sHash);
	return 0;
}

/**
Receiving from ta channel does not work if the channel is relayed.
**/
int Channel::recv(char *data, size_t maxsize, size_t minsize) const{
	//if(m_pRelay) return 0; // disable reading for a relayed connection
	//if(m_pTarget) return m_pTarget->recv(data, maxsize, minsize);
	int rc = m_ReadBuffer.recv(data, maxsize, minsize);
	if(rc>0)LOG(3, "CHANNEL: recv: "<<rc<<" bytes.");
	return rc;
	/*if(BIO_ctrl_pending(this->read_buf) < minsize || BIO_ctrl_pending(this->read_buf) == 0) return 0;
	int rc = BIO_read(read_buf, data, maxsize);*/
	//if(rc > 0) LOG(3,"CHANNEL: recv "<<rc<<" bytes.");
	//return 0;
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
	
	/*if(m_pTarget)
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
	}*/
}

	
