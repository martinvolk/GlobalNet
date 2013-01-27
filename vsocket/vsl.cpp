/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"


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
	
	// clear the data queue
	BIO_flush(in_read);
	BIO_reset(in_read);
	BIO_flush(in_write);
	BIO_reset(in_write);
	
	this->_output->connect(url);
	
	return 1;
}

Node *VSLNode::accept(){
	// accept means accepting a connection on a listening socket
	// so we have no reason to do anything if we are not in listen state
	// a node can be put in listen state by calling listen()
	if(!(this->state & CON_STATE_LISTENING) || !this->_output)
		return 0;
	
	// since peer node can't accept any connections directly, 
	// forward the code to the next node. 
	Node *peer = 0;
	if((peer = this->_output->accept())){
		// the output has a new stream connected. 
		// we need to create a new PEER node that will handle this new connection. 
		VSLNode *con = new VSLNode(m_pNetwork);
		
		// the new connection is technically not connected. 
		// it will become connected once "peer" has become connected. 
		// although in some cases the peer may already be in a connected state
		// so just in case... 
		if(!(peer->state & CON_STATE_CONNECTED))
			con->state = CON_STATE_CONNECTING;
		else
			con->state = CON_STATE_ESTABLISHED;
		
		con->url = URL("vsl", peer->url.host(), peer->url.port());
		
		// set the output to newly accepted peer
		con->_output = peer;
		
		return con;
	}
	return 0;
}

int VSLNode::listen(const URL &url){
	// listening means that we are setting up a connection in order to listen for other connections
	// since peer can not directly listen on anything, we just forward the request. 
	if(!this->_output || (this->state & CON_STATE_CONNECTED)){
		LOG("You can not listen on this socket.");
		return -1;
	}
	this->state = CON_STATE_LISTENING;
	if(this->_output->listen(url)>0){
		this->url = URL("vsl", this->_output->url.host(), this->_output->url.port());
		return 1;
	}
	return -1;
}


/**
This function packs all data as DATA packet and sends it over to the other peer
if you want to send a custom packet, use sendBlock() instead
this function should only be used to explicitly send data to the node. 
If the node has input connected then it will automatically also read
data from it's input. 
**/
int VSLNode::send(const char *data, size_t size, size_t minsize){
	// calling "send" on peer connection means that we want to send some data
	// therefore we write the data into an input buffer, and then later in the loop
	// we convert this buffer to a CMD_DATA package and send it down the line. 
	if(this->state & CON_STATE_INVALID) return -1;
	return BIO_write(this->in_write, data, size);
}

/** 
Reads a data from the decoded data queue
**/ 
int VSLNode::recv(char *data, size_t size, size_t minsize){
	// when data packets arrive, they are stripped of meta data and the data 
	// is put in the read buffer to be read using this function by the _input node. 
	// this buffer will only contain the contents of received DATA packets. 
	if(this->state & CON_STATE_INVALID) return -1;
	if(BIO_eof(this->in_read)) return 0;
	if(BIO_ctrl_pending(this->in_read) < minsize) return 0;
	return BIO_read(this->in_read, data, size);
}

/**
SendCommand is supported by nodes that support commands. Our peer node is one of them. 
A SOCKS server for example will support commands as well. If a 
**/
int VSLNode::sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag){
	// sending a command means that we want to send the data as an argument to a command
	// this function writes a command packet to the output buffer, which is then sent 
	// down the network in the main loop. inserts a command into the stream. 
	Packet pack; 
	pack.cmd.code = cmd;
	pack.cmd.size = size;
	pack.cmd.hash.from_hex_string(tag);
	memcpy(&pack.data[0], data, min(ARRSIZE(pack.data), (unsigned long)size)); 
	return sendCommand(pack);
}

int VSLNode::sendCommand(const Packet &pack){
	//LOG("VSL: sendCommand "<<pack.cmd.code<<": "<<pack.cmd.size<<" bytes data to "<<url.url());
	return BIO_write(this->write_buf, pack.c_ptr(), pack.size());
}

int VSLNode::recvCommand(Packet *dst){
	//LOG("PEER: RECV COMMAND!");
	if(this->_recv_packs.size()){
		*dst = this->_recv_packs.front();
		this->_recv_packs.pop_front();
		return 1;
	}
	return 0;
}

void VSLNode::registerChannel(const string &tag, Channel *handler){
	if(handler)
		m_Channels[tag] = handler;
	else
		ERROR("VSL: registerChannel: argument is zero!");
}

void VSLNode::removeChannel(const string &tag){
	if(!state) return;
	map<string, Channel*>::iterator it = m_Channels.find(tag);
	if(it != m_Channels.end())
		m_Channels.erase(it);
	this->sendCommand(CMD_CHAN_CLOSE, "", 0, tag);
}

void VSLNode::do_handshake(SocketType type){
	this->state = CON_STATE_CONNECTING;
	ssl->do_handshake(type); 
}
/**
This function handles incoming packets received from _output node. 
**/
void VSLNode::_handle_packet(const Packet &packet){
	// if we received DATA packet then data is stored in the buffer that will
	// be read by the _input node using our recv() function. 
	if(packet.cmd.code == CMD_DATA){
		LOG("[con_handle_packet] received DATA of "<<packet.cmd.size);
		BIO_write(this->in_read, packet.data, packet.cmd.size);
	}
	else if(packet.cmd.code == CMD_CHAN_INIT){
		LOG("VSL: received CHAN_INIT "<<packet.cmd.hash.hex()<<" from "<<url.url());
		map<string, Channel*>::iterator it = m_Channels.find(packet.cmd.hash.hex());
		if(it == m_Channels.end()){
			Channel *chan = new Channel(m_pNetwork, this, packet.cmd.hash.hex());
			m_Channels[packet.cmd.hash.hex()] = chan;
		}
		else{
			ERROR("VSL: CHAN_INIT: attempting to initialize an already registered channel!");
		}
		//m_pNetwork->registerChannel(chan);
	}
	else if(packet.cmd.code == RELAY_CONNECT){
		LOG("VSL: received RELAY_CONNECT "<<packet.cmd.hash.hex()<<"from "<<url.url());
		
	}
	// received when the relay has no more data to send or when the remote 
	// end on the relay has disconnected. Received on the client end. 
	else if(packet.cmd.code == RELAY_DISCONNECT){
		LOG("CON: relay: remote end disconnected!");
		// we need to clean up the data previously received from the relay. 
		this->state = state | CON_STATE_IDLE; 
	}
	// this one is received when a relay has successfully connected 
	// the message is sent by the BRIDGE node to it's _input once it's 
	// output goes from CONNECTING to CONNECTED. It means that the other
	// side of the bridge is now connected. 
	else if(packet.cmd.code == RELAY_CONNECT_OK){
		// we simply set our state to established as well
		// if we have another bridge monitoring us, then it will pick up on this
		this->state = CON_STATE_ESTABLISHED; 
	}
}

void VSLNode::run(){
	// receive a complete packet and store it in the packet buffer
	// if no complete packet is available, the function returns 0
	// important: the data may arrive in chunks. so we need to temporarily store 
	// a buffer with previous data and then extend it with new data until we
	// have a valid "packet". A valid packet needs to have valid checksum. 
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	if(m_bProcessingMainLoop) return;
	
	SETFLAG(m_bProcessingMainLoop, 0);
	
	if(_output)
		_output->run();
	
	for(map<string, Channel*>::iterator it = m_Channels.begin(); 
			it != m_Channels.end();){
		Channel *chan = (*it).second;
		chan->run();
		if(chan->state & CON_STATE_DISCONNECTED){
			//chan->close();
			m_Channels.erase(it++);
			//delete chan;
			continue;
		}
		it++;
	}
	
	// if we are waiting for connection and connection of the underlying node has been established
	if((this->state & CON_STATE_CONNECTING) && this->_output && (this->_output->state & CON_STATE_CONNECTED)){
		// copy the hostname 		  
		this->url = URL("vsl", this->_output->url.host(), this->_output->url.port());
		// send information about our status to the other peer. 
		
		LOG("VSL: connected to "<<url.url());
		// toggle our state to connected as well. 
		this->state = CON_STATE_ESTABLISHED;
	}
	// handle data flow if we are connected to a peer. 
	else if(this->state & CON_STATE_CONNECTED){
		// we have an extra buffer where all input data is put
		// this buffer is filled in send() function that is called by someone else
		// all this data belongs in a DATA packet. This data could not have been
		// directly writen to write_buf precisely because it needs to be formatted. 
		while((rc = BIO_read(this->in_write, tmp, SOCKET_BUF_SIZE))>0){
			LOG("[sending data] "<<rc<<" bytes to "<<url.url());
			
			this->sendCommand(CMD_DATA, tmp, rc, "");
		}
		
		/// now we process our write_buf and fill with data from _ouput
		
		// send unsent data 
		while(this->_output && !BIO_eof(this->write_buf)){
			char tmp[SOCKET_BUF_SIZE];
			int rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE);
			this->_output->send(tmp, rc);
		}
		if(this->_output && (rc = this->_output->recv(tmp, sizeof(tmp)))>0){
			BIO_write(m_pPacketBuf, tmp, rc);
		}
		
		// if enough data is in the buffer, we decode the packet 
		if(!m_bPacketReadInProgress){
			if(BIO_ctrl_pending(m_pPacketBuf) >= sizeof(m_CurrentPacket.cmd)){
				//LOG("VSL: reading packet header..");
				m_bPacketReadInProgress = true;
				BIO_read(m_pPacketBuf, &m_CurrentPacket.cmd, sizeof(m_CurrentPacket.cmd));
				if(!m_CurrentPacket.cmd.is_valid()){
					ERROR("VSL: "<<url.url()<<": CORRUPTED PACKET STREAM!");
					close();
					return;
				}
			}
		}
		else {
			if(BIO_ctrl_pending(m_pPacketBuf) >= m_CurrentPacket.cmd.size){
				BIO_read(m_pPacketBuf, m_CurrentPacket.data, m_CurrentPacket.cmd.size);
				m_CurrentPacket.data[m_CurrentPacket.cmd.size] = 0;
				m_CurrentPacket.source = this;

				if(!m_CurrentPacket.cmd.hash.is_zero()){
					map<string, Channel*>::iterator h = m_Channels.find(m_CurrentPacket.cmd.hash.hex()); 
					if(h != m_Channels.end()){
						//LOG("VSL: passing packet to listener "<<m_CurrentPacket.cmd.hash.hex());
						(*h).second->handlePacket(m_CurrentPacket);
					}
					else{
						//LOG("VSL: handling packet "<<m_CurrentPacket.cmd.hash.hex());
						_handle_packet(m_CurrentPacket);
					}
				}
				
				
				this->_recv_packs.push_back(m_CurrentPacket);
					
				m_bPacketReadInProgress = false;
			}
		}
	}
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(this->_output && this->_output->state & CON_STATE_DISCONNECTED){
		//LOG("PEER: underlying connection lost. Disconnected!");
		this->state = CON_STATE_DISCONNECTED;
	}
}

void VSLNode::close(){
	// send unsent data 
	if(!this->_output){
		this->state = CON_STATE_DISCONNECTED;
		return;
	}
	while(!BIO_eof(this->write_buf)){
		char tmp[SOCKET_BUF_SIZE];
		int rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE);
		this->_output->send(tmp, rc);
	}
	LOG("PEER: disconnected!");
	this->_output->close();
	this->state = CON_STATE_WAIT_CLOSE;
}

void VSLNode::set_output(Node *other){
	delete this->_output->_output;
	this->_output->_output = other;
	if(other){
		// ugly 
		this->url = URL("vsl", other->url.host(), other->url.port());
		this->_output->url = URL("ssl", other->url.host(), other->url.port());
		other->set_input(this);
	}
}
Node* VSLNode::get_output(){
	if(this->_output->_output)
		return this->_output->_output;
	return this->_output;
}
/*
void VSLNode::set_input(Node *other){ 
	this->_input = other;
	other->set_output(this);
}

Node* VSLNode::get_input(){
	return this->_input;
}
*/

VSLNode::VSLNode(Network *net):Node(net){
	ssl = new SSLNode(net);
	udt = new UDTNode(net);
	
	ssl->_output = udt;
	udt->_input = ssl;
	ssl->_input = this;
	this->_output = ssl;
	
	this->m_pPacketBuf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(this->m_pPacketBuf, -1);
	
	m_bPacketReadInProgress = false;
	this->type = NODE_PEER;
}

VSLNode::~VSLNode(){
	LOG("VSL: deleting "<<url.url());
	state = 0;
	for(map<string, Channel*>::iterator it = m_Channels.begin(); 
			it != m_Channels.end(); it++){
		(*it).second->close();
	}
	
}

