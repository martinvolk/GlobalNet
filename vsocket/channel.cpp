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
	for(map<uint32_t, ChannelRemoteConnection*>::iterator i = m_RemoteClients.begin();
		i != m_RemoteClients.end(); i++){
		(*i).second->detach();
	}
	
	this->close();
}

// only accessible to ChannelRemoteConnection
void Channel::unlinkRemoteConnection(uint32_t tag){
	map<uint32_t, ChannelRemoteConnection*>::iterator i = m_RemoteClients.find(tag);
	if(i != m_RemoteClients.end())
		m_RemoteClients.erase(i);
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
	else if(pack.cmd.code == CMD_REMOTE_LISTEN){
		URL url = URL(pack.data.data());
		unique_ptr<Node> connection; 
		if(url.protocol() == "tcp")
			connection = unique_ptr<Node>(new TCPNode(m_pNetwork));
		else if(url.protocol() == "udt")
			connection = unique_ptr<Node>(new UDTNode(m_pNetwork));
		else if(url.protocol() == "vsl")
			connection = unique_ptr<Node>(new VSLNode(m_pNetwork, 
					unique_ptr<Node>(new SSLNode(m_pNetwork, 
						unique_ptr<Node>(new UDTNode(m_pNetwork)), SOCK_SERVER
					))
				)
			);
			
		connection->listen(url);
		if(connection->state & CON_STATE_LISTENING){
			m_pListenSocket = move(connection);
			
			this->sendCommand(CMD_REMOTE_LISTEN_SUCCESS, "", 0, m_sHash);
		}
	}
	else if(pack.cmd.code == CMD_REMOTE_LISTEN_SUCCESS){
		LOG(3, "CHANNEL: remote listen success!");
		state = CON_STATE_LISTENING;
	}
	else if(pack.cmd.code == CMD_REMOTE_LISTEN_DATA){
		uint32_t id = ntohl(*(uint32_t*)pack.data.data());
		vector<char> data = vector<char>(pack.data.data()+sizeof(id), pack.data.data()+pack.data.size());
		//data[data.size()] = 0;
		LOG(3, "CHANNEL: remote listen data id: "<<id);
		
		if(m_RemoteClients.find(id) != m_RemoteClients.end()){
			LOG(3, "CHANNEL: received remote listen data!");
			m_RemoteClients[id]->handleData(data.data(), data.size());
		}
		else if(m_ListenClients.find(id) != m_ListenClients.end()){
			LOG(3, "CHANNEL: received data for listen socket!");
			m_ListenClients[id]->send(data.data(), data.size());
		}
	}
	else if(pack.cmd.code == CMD_REMOTE_LISTEN_CLIENT_CONNECTED){
		uint32_t id = ntohl(*(uint32_t*)pack.data.data());
		
		LOG(3, "CHANNEL: remote listen client connected! "<<id);
		
		m_AcceptQueue.push_back(pair<uint32_t, ChannelRemoteConnection*>(id, new ChannelRemoteConnection(m_pNetwork, this, id)));
	}
	else if(pack.cmd.code == CMD_REMOTE_LISTEN_CLIENT_DISCONNECTED){
		LOG(3, "CHANNEL: remote listen client disconnected!");
		uint32_t id = ntohl(*(uint32_t*)pack.data.data());
		map<uint32_t, ChannelRemoteConnection*>::iterator c = m_RemoteClients.find(id);
		if(c != m_RemoteClients.end()){
			(*c).second->detach();
			m_RemoteClients.erase(c);
		}
	}
	else if(state & CON_STATE_CONNECTED){
		if(pack.cmd.code == CMD_DATA){
			LOG(2,"CHANNEL: DATA at "<<url.url()<<", "
					<<pack.cmd.hash.hex()<<": "<<pack.data.size()<<" bytes.");
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
	LOG(3, "CHANNEL: listen: "<<url.url());
	if(m_extLink)
		m_extLink->sendCommand(CMD_REMOTE_LISTEN, url.url().c_str(), url.url().length(), m_sHash);
	return 1;
}

unique_ptr<Node> Channel::accept(){
	if(m_AcceptQueue.size()){
		pair<uint32_t, ChannelRemoteConnection*> p = *m_AcceptQueue.begin();
		m_RemoteClients[p.first] = p.second;
		m_AcceptQueue.pop_front();
		return unique_ptr<ChannelRemoteConnection>(p.second);
	}
	return unique_ptr<Node>();
}

void Channel::run(){
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	//for(map<uint32_t, unique_ptr<Node> >::iterator i = m_ListenClients.begin();
	//	i != m_ListenClients.end(); i++){
	if(m_pListenSocket){
		unique_ptr<Node> client = m_pListenSocket->accept();
		if(client){
			uint32_t id = rand();
			while(m_ListenClients.find(id) != m_ListenClients.end())
				id = rand();
			m_ListenClients[id] = move(client);
			LOG(3, "CHANNEL: listen client connected! "<<id);	
			id = htonl(id);
			this->sendCommand(CMD_REMOTE_LISTEN_CLIENT_CONNECTED, (char*)&id, sizeof(id), "");
		}
	}
	
	for(map<uint32_t, unique_ptr<Node> >::iterator i = m_ListenClients.begin();
		i != m_ListenClients.end(); i++){
		(*i).second->run();
		if((*i).second->state & CON_STATE_INVALID){
			uint32_t id = htonl((*i).first);
			this->sendCommand(CMD_REMOTE_LISTEN_CLIENT_DISCONNECTED, (char*)&id, sizeof(id), "");
			m_ListenClients.erase(i);
			break;
		}
		if((rc = (*i).second->recv(tmp, SOCKET_BUF_SIZE)) > 0){
			LOG(3, "CHANNEL: received data from listen socket "<<(*i).first);
			vector<char> data; 
			data.resize(rc+sizeof((*i).first));
			uint32_t id = htonl((*i).first);
			memcpy(data.data(), &id, sizeof(id));
			memcpy(data.data()+sizeof(id), tmp, rc);
			this->sendCommand(CMD_REMOTE_LISTEN_DATA, data.data(), data.size(), "");
		}
	}
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

ChannelRemoteConnection::ChannelRemoteConnection(weak_ptr<Network> net, Channel* link, uint32_t tag)
	: Node(net), m_pChannel(link), m_iTag(tag) {
	state = CON_STATE_CONNECTED;
}

ChannelRemoteConnection::~ChannelRemoteConnection(){
	this->close();
}

int ChannelRemoteConnection::send(const char *data, size_t size){
	string str = to_string(m_iTag);
	vector<char> pack; 
	uint32_t id =  htonl(m_iTag);
	pack.resize(size+sizeof(id));
	memcpy(pack.data(), &id, sizeof(id));
	memcpy(&pack[sizeof(id)], data, size);
	if(!m_pChannel) return 0; 
	
	m_pChannel->sendCommand(CMD_REMOTE_LISTEN_DATA, pack.data(), pack.size(), "");
	return size;
}

int ChannelRemoteConnection::recv(char *data, size_t maxsize, size_t minsize) const{
	int rc = m_ReadBuffer.recv(data, maxsize, minsize);
	if(rc>0)LOG(3, "CHANNEL REMOTE: recv: "<<rc<<" bytes.");
	return rc;
}

void ChannelRemoteConnection::handleData(const char *data, size_t size){
	LOG(3, "CHANNEL REMOTE CONNECTION: handleData");
	m_ReadBuffer.sendOutput(data, size);
}

void ChannelRemoteConnection::detach(){
	state = CON_STATE_DISCONNECTED;
	m_pChannel = 0;
}

void ChannelRemoteConnection::close(){
	string str = to_string(m_iTag);
	if(m_pChannel){
		m_pChannel->sendCommand(CMD_REMOTE_LISTEN_CLOSE, str.c_str(), str.length(), "");
		m_pChannel->unlinkRemoteConnection(m_iTag);
	}
}
