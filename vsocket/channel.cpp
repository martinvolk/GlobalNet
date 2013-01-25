#include "local.h"

Channel::Channel(VSLNode *link, const string &hash):
	m_pRelay(0), m_pLink(link){
	
	if(!hash.length()){
		stringstream ss;
		ss<<time(0)<<rand();
		Packet p;
		p.cmd.code = CMD_CHAN_INIT;
		p.cmd.hash = SHA1Hash::compute(ss.str());
		m_sHash = p.cmd.hash.hex();
		m_pLink->sendCommand(p);
	} else {
		m_sHash = hash;
	}
	m_pLink->setPacketHandler(m_sHash, this);
}

Channel::~Channel(){
	this->close();
	m_pLink->removePacketHandler(m_sHash);
}

void Channel::handlePacket(const Packet &pack){
	if(pack.cmd.code == RELAY_CONNECT_OK){
		state = CON_STATE_ESTABLISHED; 
	}
	else if(pack.cmd.code == CMD_CHAN_INIT){
		LOG("CHANNEL: received CHAN_INIT "<<pack.cmd.hash.hex()<<" from "<<url.url());
	}
	else if(pack.cmd.code == CMD_DATA){
		LOG("CHANNEL: DATA from "<<m_pLink->url.url()<<": "<<pack.cmd.size<<" bytes.");
		if(m_pRelay)
			m_pRelay->send(pack.data, pack.cmd.size);
		else
			BIO_write(read_buf, pack.data, pack.cmd.size);
	}
	else if(pack.cmd.code == CMD_ENCRYPT_BEGIN){
		LOG("CHANNEL: ENCRYPT_BEGIN from "<<m_pLink->url.url());
		VSLNode *node = new VSLNode();
		node->set_output(this);
		node->do_handshake(SOCK_SERVER);
		m_pNetwork->registerPeer(node);
	}
	
	else if(pack.cmd.code == RELAY_CONNECT){
		URL url = URL(pack.data);
		LOG("CHANNEL: got relay connect from "<<m_pLink->url.url()<<": "<<url.url());
		// this will either return an existing connection or establish a new one
		if(url.protocol().compare("tcp") == 0){
			Node *con = new TCPNode();
			con->connect(url);
			m_pRelay = con;
		}
	}
}

int Channel::connect(const URL &url){
	Packet pack;
	pack.cmd.code = RELAY_CONNECT;
	pack.cmd.hash.from_hex_string(m_sHash);
	pack.cmd.size = url.url().length();
	memcpy(pack.data, url.url().c_str(), url.url().length());
	return m_pLink->sendCommand(pack);
}

int Channel::sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag){
	return m_pLink->sendCommand(cmd, data, size, m_sHash);
}
int Channel::send(const char *data, size_t maxsize, size_t minsize){
	return m_pLink->sendCommand(CMD_DATA, data, maxsize, m_sHash);
}

int Channel::recv(char *data, size_t maxsize, size_t minsize){
	if(m_pRelay) return 0; // disable reading for a relayed connection
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

void Channel::run(){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	// shuffle data between us and the relay. 
	if(m_pRelay){// read data from one end and forward it to the other end and vice versa
		m_pRelay->run();
		
		if ((rc = m_pRelay->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG("CHANNEL: read "<<rc<<" bytes from relayed connection..");
			this->send(tmp, rc);
		}
		if(BIO_ctrl_pending(read_buf)>0){
			if((rc = BIO_read(read_buf, tmp, SOCKET_BUF_SIZE))>0)
				m_pRelay->send(tmp, rc);
		}
	}
}

void Channel::close(){
	//m_pLink->sendCommand(CMD_CHAN_CLOSE, m_sHash.c_str(), m_sHash.length());
}
	
