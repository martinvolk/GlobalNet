/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"


int VSLNode::connect(const char *hostname, uint16_t port){ 
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
	this->_output->connect(hostname, port);
	
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
		VSLNode *con = new VSLNode(0);
		
		// the new connection is technically not connected. 
		// it will become connected once "peer" has become connected. 
		// although in some cases the peer may already be in a connected state
		// so just in case... 
		if(!(peer->state & CON_STATE_CONNECTED))
			con->state = CON_STATE_CONNECTING;
		else
			con->state = CON_STATE_ESTABLISHED;
		
		con->host = peer->host;
		con->port = peer->port;
		
		// set the output to newly accepted peer
		con->_output = peer;
		
		return con;
	}
	return 0;
}

int VSLNode::listen(const char *host, uint16_t port){
	// listening means that we are setting up a connection in order to listen for other connections
	// since peer can not directly listen on anything, we just forward the request. 
	if(!this->_output || (this->state & CON_STATE_CONNECTED)){
		LOG("You can not listen on this socket.");
		return -1;
	}
	this->state = CON_STATE_LISTENING;
	if(this->_output->listen(host, port)>0){
		this->host = this->_output->host;
		this->port = this->_output->port;
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
int VSLNode::send(const char *data, size_t size){
	// calling "send" on peer connection means that we want to send some data
	// therefore we write the data into an input buffer, and then later in the loop
	// we convert this buffer to a CMD_DATA package and send it down the line. 
	if(this->state & CON_STATE_INVALID) return -1;
	return BIO_write(this->in_write, data, size);
}

/** 
Reads a data from the decoded data queue
**/ 
int VSLNode::recv(char *data, size_t size){
	// when data packets arrive, they are stripped of meta data and the data 
	// is put in the read buffer to be read using this function by the _input node. 
	// this buffer will only contain the contents of received DATA packets. 
	if(this->state & CON_STATE_INVALID) return -1;
	if(BIO_eof(this->in_read)) return 0;
	return BIO_read(this->in_read, data, size);
}

/**
SendCommand is supported by nodes that support commands. Our peer node is one of them. 
A SOCKS server for example will support commands as well. If a 
**/
int VSLNode::sendCommand(NodeMessage cmd, const char *data, size_t size){
	// sending a command means that we want to send the data as an argument to a command
	// this function writes a command packet to the output buffer, which is then sent 
	// down the network in the main loop. inserts a command into the stream. 
	Packet pack; 
	pack.cmd.code = cmd;
	pack.cmd.size = size;
	memcpy(&pack.data[0], data, min(ARRSIZE(pack.data), (unsigned long)size)); 
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

/*** sets up this connection so that it's output is sent to "other"
// instead of the default UDT socket. 
***/

void VSLNode::peg(Node *other){
	// this function pegs the output of our SSL node as input to another node 
	// we need to override the default function because we have a custom structure
	
	// close the udt connection and connect the output of the 
	// ssl connection to the input of this peer 
	Node *udt = this->_output->_output;
	udt->close(); 
	
	// now bridge the end of the ssl connection with "other"
	this->_output->_output = other;
	other->_input = this->_output;
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
	// received when the relay has no more data to send or when the remote 
	// end on the relay has disconnected. Received on the client end. 
	else if(packet.cmd.code == RELAY_DISCONNECT){
		LOG("CON: relay: remote end disconnected!");
		this->state = state | CON_STATE_IDLE; 
	}
	// this one is sent as a request to make current node connect to a different host
	// the request will originate from _output and the new connection should be 
	// connected to _input. Then all data sent by the input will be sent to the output. 
	else if(packet.cmd.code == RELAY_CONNECT){
		// receiving a connect when we already have an input node is invalid
		// although in the future it may be useful as a way to reuse intermediate peer links. 
		if(this->_input){
			//ERROR("RELAY_CONNECT received when we already have an _input node.");
			
			// prevent recursive delete
			if(this->_input->_input == this)
				this->_input->_input = 0;
			if(this->_input->_output == this)
				this->_input->_output = 0;
			delete _input;
		}
		// data contains a string of format PROTO:IP:PORT
		char tmp[SOCKET_BUF_SIZE];
		memcpy(tmp, packet.data, min((unsigned long)SOCKET_BUF_SIZE, (unsigned long)packet.cmd.size));
		tmp[packet.cmd.size] = 0;
		
		string str = string(tmp);
		vector<string> tokens;
		tokenize(str, ":",tokens);
		string proto = "udt";
		string host ;
		uint16_t port = 9000;
		if(tokens.size() == 3){
			proto = tokens[0];
			host = tokens[1];
			port = atoi(tokens[2].c_str());
		} else if(tokens.size() == 2){
			host = tokens[0];
			port = atoi(tokens[1].c_str());
		}
		
		stringstream err;
		
		INFO("[relay] connecting to: "<<host<<":"<<port);
		
		// before we start forwarding data (done in the main loop)
		// we create a new connection and issue a connect on it which 
		// connects it to host. In order to ensure correct forwarding of all
		// calls, we also have to set up a "bridge" node which will act as
		// an adapter passing data between the two inputs. 
		// this is important, because since we are connecting two _inputs, 
		// if for example one of them goes into disconnect, the other one will
		// have no idea about it because it is only responsible for monitoring
		// it's _output. A bridge will monitor the connection state and appropriately
		// send a disconnect to the other node that is connected to it. 
		Node *other = Node::createNode(proto.c_str());
		BridgeNode *bridge = new BridgeNode();
		
		other->connect(host.c_str(), port);
		
		// self<->bridge<->other
		bridge->_input = this;
		this->_input = bridge; 
		bridge->_output = other; 
		other->_input = bridge;
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
	
	// ugly
	if(_input && _input->type == NODE_BRIDGE) _input->run();
	Node::run();
	
	// if we are waiting for connection and connection of the underlying node has been established
	if((this->state & CON_STATE_CONNECTING) && this->_output && (this->_output->state & CON_STATE_CONNECTED)){
		// copy the hostname 		  
		this->host = this->_output->host;
		this->port = this->_output->port;
		// send information about our status to the other peer. 
		
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
			//LOG("[sending data] "<<rc<<" bytes to "<<this->host<<":"<<this->port);
			
			this->sendCommand(CMD_DATA, tmp, rc);
		}
		
		/// now we process our write_buf and fill read_buf with data from _ouput
		
		// send unsent data 
		while(this->_output && !BIO_eof(this->write_buf)){
			char tmp[SOCKET_BUF_SIZE];
			int rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE);
			this->_output->send(tmp, rc);
		}
		
		// attempt to receive some data from the underlying connection and decode it
		if(this->_output && (rc = this->_output->recv(tmp, sizeof(tmp)))>0){
			int start = this->_recv_buf.size();
			this->_recv_buf.resize(this->_recv_buf.size()+rc);
			memcpy(&this->_recv_buf[start], tmp, rc);
			
			// try to read as many complete packets as possible from the recv buf
			while(this->_recv_buf.size()){
				// now we need to check if the packet is complete
				PacketHeader *cmd = (PacketHeader*)&this->_recv_buf[0];
				Packet packet;
				if(cmd->size <= this->_recv_buf.size()-sizeof(PacketHeader)){
					// check checksum here
					unsigned size = min(ARRSIZE(packet.data), (unsigned long)cmd->size);
					if(size < cmd->size){
						ERROR("Packet exceeds maximum allowed size!");
						return;
					}
					memcpy(packet.data, &this->_recv_buf[0]+sizeof(PacketHeader), size);
					memcpy(&packet.cmd, cmd, sizeof(PacketHeader));
					packet.data[size] = 0;
					packet.source = this;
					
					LOG("CON_process: received complete packet at "<<this->host<<":"<<this->port<<" cmd: "<<
						packet.cmd.code<<" datalength: "<<rc);
					//packet.cmd.size<<" recvsize: "<<this->_recv_buf.size());
					
					// if we have an output socket then we write the received data directly to that socket
					//LOG(this->bridge);
					_handle_packet(packet);
					
					this->_recv_packs.push_back(packet);
					
					// update the recv_buf to only have the trailing data that has not 
					// yet been decoded. 
					this->_recv_buf = vector<char>(
						this->_recv_buf.begin()+cmd->size+sizeof(PacketHeader), 
						this->_recv_buf.end());
				} else {
					LOG("CON_process: received partial data of "<<rc<< " bytes "<<(this->_recv_buf.size()-sizeof(PacketHeader)));
					break;
				}
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
	other->set_input(this);
}
void VSLNode::set_input(Node *other){ 
	this->_input = other;
	other->set_output(this);
}
Node* VSLNode::get_output(){
	return this->_output->_output;
}
Node* VSLNode::get_input(){
	return this->_input;
}

VSLNode::VSLNode(Node *next){
	if(!next){
		SSLNode *ssl = new SSLNode();
		UDTNode *udp = new UDTNode();
		
		ssl->_output = udp;
		udp->_input = ssl;
		ssl->_input = this;
		this->_output = ssl;
	} else {
		this->_output = next;
	}
	
	this->type = NODE_PEER;
}

VSLNode::~VSLNode(){
	//LOG("VSL: deleting "<<this->host<<":"<<this->port);
	
	
}

