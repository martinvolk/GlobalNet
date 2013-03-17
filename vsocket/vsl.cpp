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


VSLNode::VSLNode(weak_ptr<Network> net, unique_ptr<Node> out):Node(net){
	if(!out) throw std::exception();
	
	m_pTransportLayer = move(out);
	
	m_bPacketReadInProgress = false;
	m_bReleasingChannel = false;
	
	// the new connection is technically not connected. 
	// it will become connected once "peer" has become connected. 
	// although in some cases the peer may already be in a connected state
	// so just in case... 
	if(!(m_pTransportLayer->state & CON_STATE_CONNECTED))
		this->state = CON_STATE_CONNECTING;
	else
		this->state = CON_STATE_ESTABLISHED;
	
	this->url = URL("vsl", m_pTransportLayer->url.host(), m_pTransportLayer->url.port());
	
	this->type = NODE_PEER;
}

VSLNode::~VSLNode(){
	LOG(3,"VSL: deleting "<<url.url());
	state = 0;
	close(); //?? safe?
	for(map<string, Channel*>::iterator it = m_Channels.begin(); 
			it != m_Channels.end(); it++){
		(*it).second->detach();
	}
	/* No more need to do this with weak ptr :)
=======
	//close(); //?? safe?
	
>>>>>>> master
	list<Channel*> chans;
	for(map<string, Channel*>::iterator it = m_Channels.begin(); 
			it != m_Channels.end(); it++){
		chans.push_back((*it).second);
	}
	for(list<Channel*>::iterator it = chans.begin(); 
			it != chans.end(); it++){
		//(*it)->m_extLink = 0;
		//sendCommand(CMD_CHAN_CLOSE, "", 0, (*it)->id());
		releaseChannel(*it);
	}*/
	m_Channels.clear();
}


void VSLNode::close(){
	// send unsent data 
	if(!m_pTransportLayer->state & CON_STATE_DISCONNECTED){
		this->state = CON_STATE_DISCONNECTED;
		return;
	}
	
	LOG(1,"PEER: disconnected!");
	m_pTransportLayer->close();
	this->state = CON_STATE_WAIT_CLOSE;
}

unique_ptr<Channel> VSLNode::createChannel(){
	unique_ptr<Channel> chan(new Channel(m_pNetwork, this)); 
	m_Channels[chan->id()] = chan.get();
	return chan;
}

void VSLNode::releaseChannel(const string &tag){
	if(m_bReleasingChannel) return;
	m_bReleasingChannel = true;
	
	map<string, Channel* >::iterator it = m_Channels.find(tag);
	if(it != m_Channels.end()){
		// remove it if it is internally created
		this->sendCommand(CMD_CHAN_CLOSE, "", 0, (*it).second->id());
		m_Channels.erase(it);
	}
	m_bReleasingChannel = false;
}

int VSLNode::connect(const URL &url){ 
	if(this->state & CON_STATE_CONNECTED){
		cout<<"CON_connect: connection is already connected. Please call CON_close() before establishing a new one!"<<endl;
		return 0;
	}
	// we don't support direct connections so we forward the request 
	// will get forwarded until it reaches a node that supports connections
	// normally the next node will be SSL which will forward to UDT
	// once the connection succeeds, the underlying node will change it's 
	// state to CON_STATE_ESTABLISHED. There is no direct way to check
	// if connection was successful. Some kind of timeout will work better. 
	this->state = CON_STATE_CONNECTING;
	
	m_PacketBuf.clear();
	
	this->url = url;
	m_pTransportLayer->connect(url);
	
	return 1;
}

int VSLNode::connect(const unique_ptr<Channel> &hub, const URL &peer){
	URL target = URL("vsl", peer.host(), rand()%63536+2000);
	hub->sendCommand(Packet(CMD_CONNECT_RZ_REQUEST, target.url().c_str(), target.url().length(), ""));
	//m_pTransportLayer->set_option("rendezvous", "1");
	m_pTransportLayer->bind(URL("udt", "localhost", target.port()));
	m_pTransportLayer->connect(URL("udt", target.host(), target.port()));
	this->state = CON_STATE_CONNECTING;
	m_tConnectInitTime = time(0);
	return 0;
}

int VSLNode::bind(const URL &url){
	return m_pTransportLayer->bind(url);
}

unique_ptr<Node> VSLNode::accept(){
	// accept means accepting a connection on a listening socket
	// so we have no reason to do anything if we are not in listen state
	// a node can be put in listen state by calling listen()
	if(!(this->state & CON_STATE_LISTENING))
		return unique_ptr<Node>();
	
	// since peer node can't accept any connections directly, 
	// forward the code to the next node. 
	unique_ptr<Node> peer;
	if((peer = m_pTransportLayer->accept())){
		LOG(3, "VSL: accepted new connection from "<<peer->url.url());
		// the output has a new stream connected. 
		// we need to create a new PEER node that will handle this new connection. 
		unique_ptr<VSLNode> con(new VSLNode(m_pNetwork, move(peer)));
		return move(con);
	}
	return unique_ptr<Node>();
}

int VSLNode::listen(const URL &url){
	// listening means that we are setting up a connection in order to listen for other connections
	// since peer can not directly listen on anything, we just forward the request. 
	if(this->state & CON_STATE_CONNECTED){
		ERROR("VSL: can not listen on an already connected socket!");
		return -1;
	}
	this->state = CON_STATE_LISTENING;
	if(m_pTransportLayer->listen(url)>0){
		this->url = URL("vsl", m_pTransportLayer->url.host(), m_pTransportLayer->url.port());
		return 1;
	}
	return -1;
}

/*
This function packs all data as DATA packet and sends it over to the other peer
if you want to send a custom packet, use sendBlock() instead
this function should only be used to explicitly send data to the node. 
If the node has input connected then it will automatically also read
data from it's input. 
*/

int VSLNode::send(const char *data, size_t size){
	ERROR("VSL: send is not implemented!");
	return 0;
}

int VSLNode::recv(char *data, size_t size, size_t minsize) const{
	ERROR("VSL: recv is not implemented!");
	return 0;
}

int VSLNode::sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag){
	Packet r;
	r.cmd.code = cmd;
	r.cmd.size = size;
	r.cmd.hash.from_hex_string(tag); 
	r.data.resize(size);
	std::copy(data, data+size, r.data.begin());
	return sendCommand(r);
}

int VSLNode::sendCommand(const Packet &pack){
	LOG(3,"VSL: sendCommand "<<pack.cmd.code<<": "<<pack.cmd.size<<" bytes data to "<<url.url());
	PacketHeader cmd = pack.cmd;
	cmd.size = pack.data.size();
	vector<char> tmp(sizeof(PacketHeader)+pack.data.size());
	std::copy((char*)&cmd, ((char*)&cmd) + sizeof(PacketHeader), tmp.begin());
	std::copy(pack.data.begin(), pack.data.end(), tmp.begin()+sizeof(PacketHeader));
	if(sizeof(PacketHeader)+pack.data.size() == tmp.size())
		m_pTransportLayer->send(tmp.data(), tmp.size());
	else 
		ERROR("VSL: sendCommand: allocation error!");
	return pack.size();
}
/*
void VSLNode::do_handshake(SocketType type){
	this->state = CON_STATE_CONNECTING;
	m_pTransportLayer->do_handshake(type); 
}*/
/**
This function handles incoming packets received from output() node. 
**/
void VSLNode::_handle_packet(const Packet &packet){
	// if we received DATA packet then data is stored in the buffer that will
	// be read by the _input node using our recv() function. 
	if(packet.cmd.code == CMD_DATA){
		LOG(2,"[con_handle_packet] received DATA of "<<packet.cmd.size);
		//BIO_write(this->in_read, packet.data, packet.cmd.size);
	}
	else if(packet.cmd.code == CMD_CHAN_INIT){
		LOG(2,"VSL: "<<this<<" received CHAN_INIT "<<packet.cmd.hash.hex()<<" from "<<url.url());
		map<string, Channel* >::iterator it = m_Channels.find(packet.cmd.hash.hex());
		if(it == m_Channels.end()){
			//shared_ptr<Network> net = m_pNetwork.lock();
			//if(net) net->onChannelConnected(packet.cmd.hash.hex());
			Channel *ch = new Channel(m_pNetwork, this, packet.cmd.hash.hex());
			m_Channels[packet.cmd.hash.hex()] = ch; // this is ok since Channel automatically unregisters itself upon deletion 
			unique_ptr<Channel> chan(ch);
			shared_ptr<Network> net = m_pNetwork.lock();
			if(net){
				net->onChannelConnected(move(chan));
			}
		}
		else{
			ERROR("VSL: CHAN_INIT: attempting to initialize an already registered channel!");
		}
	}
}

void VSLNode::run(){
	// receive a complete packet and store it in the packet buffer
	// if no complete packet is available, the function returns 0
	// important: the data may arrive in chunks. so we need to temporarily store 
	// a buffer with previous data and then extend it with new data until we
	// have a valid "packet". A valid packet needs to have valid checksum. 

	//if(m_bProcessingMainLoop) return;
	
	//SETFLAG(m_bProcessingMainLoop, 0);
	
	m_pTransportLayer->run();
	
	// go through the array of channels and delete disconnected ones. 
	for(map<string, Channel* >::iterator it = m_Channels.begin(); 
			it != m_Channels.end();){
		if((*it).second->state & CON_STATE_DISCONNECTED){
			(*it).second->m_extLink = 0;
			(*it).second->close();
			// send channel close notification to the other end. 
			this->sendCommand(Packet(CMD_CHAN_CLOSE, "", 0, (*it).second->id()));
			m_Channels.erase(it++);
			continue;
		}
		(*it).second->run();
		it++;
	}
	
	// if we are waiting for connection and connection of the underlying node has been established
	if(!(this->state & CON_STATE_CONNECTED) && (m_pTransportLayer->state & CON_STATE_CONNECTED)){
		// copy the hostname 		  
		this->url = URL("vsl", m_pTransportLayer->url.host(), m_pTransportLayer->url.port());
		// send information about our status to the other peer. 
		
		LOG(1,"VSL: connected to "<<url.url());
		// toggle our state to connected as well. 
		this->state = CON_STATE_ESTABLISHED;
	}
	// handle data flow if we are connected to a peer. 
	if(this->state & CON_STATE_CONNECTED){
		// parse packets
		if(!m_bPacketReadInProgress){	
			if(m_pTransportLayer->input_pending() >= sizeof(m_CurrentPacket.cmd)){
				m_bPacketReadInProgress = true;
				LOG(3, "VSL: reading packet header from "<<url.url());
				m_pTransportLayer->recv((char*)&m_CurrentPacket.cmd, sizeof(PacketHeader), sizeof(PacketHeader));
				if(!m_CurrentPacket.cmd.is_valid()){
					ERROR("VSL: "<<url.url()<<": CORRUPTED PACKET STREAM!");
					close();
					return;
				}
			}
		}
		else {
			if(m_pTransportLayer->input_pending() >= m_CurrentPacket.cmd.size){
				m_CurrentPacket.data.resize(m_CurrentPacket.cmd.size);
				if(m_CurrentPacket.data.size() != m_CurrentPacket.cmd.size){
					ERROR("ALLOCATION ERROR!");
					close();
					return;
				}
				m_pTransportLayer->recv(m_CurrentPacket.data.data(), m_CurrentPacket.cmd.size);
				
				// pass the packet to the channel
				if(!m_CurrentPacket.cmd.hash.is_zero()){
					map<string, Channel* >::iterator h = m_Channels.find(m_CurrentPacket.cmd.hash.hex()); 
					if(h != m_Channels.end()){
						LOG(2,"VSL: "<<this<<" passing packet to listener "<<m_CurrentPacket.cmd.hash.hex()<<": "<<m_CurrentPacket.cmd.size<<" bytes. CMD: "<<m_CurrentPacket.cmd.code);
						(*h).second->handlePacket(m_CurrentPacket);
					}
					else{
						_handle_packet(m_CurrentPacket);
					}
				}
				m_bPacketReadInProgress = false;
			}
		}
	}
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(m_pTransportLayer->state & CON_STATE_DISCONNECTED){
		//LOG(1,"PEER: underlying connection lost. Disconnected!");
		this->state = CON_STATE_DISCONNECTED;
	}
}
/*
const Node &operator<<(vector<char> &data, const Node &buf){
	size_t minsize = data.size();
	data.resize(data.capacity());
	buf.recv(data.data(), data.size(), minsize);
	return buf;
}
const Node &operator<<(PacketHeader &head, const Node &buf){
	buf.recv((char*)&head, sizeof(PacketHeader), sizeof(PacketHeader));
	return buf;
}
Node &operator>>(const vector<char> &data, Node &buf){
	buf.send(data.data(), data.size());
	//buf.sendCommand(Packet(CMD_DATA, data.data(), data.size(), ""));
	return buf;
}
Node &operator>>(const PacketHeader &data, Node &buf){
	buf.send((char*)&data, sizeof(PacketHeader));
	return buf;
}
Node &operator<<(Node &buf, const vector<char> &data){
	buf.sendOutput(data.data(), data.size());
	return buf;
}
const Node &operator>>(const Node &buf, vector<char> &data){
	size_t minsize = data.size();
	data.resize(data.capacity());
	buf.recvOutput(data.data(), data.size(), minsize);
	return buf;
}

Node &operator>>(const Packet &pack, Node &buf){
	buf.sendCommand(pack);
	return buf;
}
*/
/*
void VSLNode::set_input(Node *other){ 
	this->_input = other;
	other->setOutput(this);
}

Node* VSLNode::get_input(){
	return this->_input;
}
*/

