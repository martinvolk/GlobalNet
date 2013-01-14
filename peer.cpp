#include "gclient.h"

struct peer_data_t{
	Connection *peer;
};

int _peer_connect(Connection &self, const char *hostname, uint16_t port){ 
	if(self.state & CON_STATE_CONNECTED){
		cout<<"CON_connect: connection is already connected. Please call CON_close() before establishing a new one!"<<endl;
		return 0;
	}
	// we don't support direct connections so we forward the request 
	// will get forwarded until it reaches a node that supports connections
	// normally the next node will be SSL which will forward to UDT
	// once the connection succeeds, the underlying node will change it's 
	// state to CON_STATE_ESTABLISHED. There is no direct way to check
	// if connection was successful. Some kind of timeout will work better. 
	self.state = CON_STATE_CONNECTING;
	self._output->connect(*self._output, hostname, port));
	
	return 1;
}

Connection *_peer_accept(Connection &self){
	// accept means accepting a connection on a listening socket
	// so we have no reason to do anything if we are not in listen state
	// a node can be put in listen state by calling listen()
	if(!(self.state & CON_STATE_LISTENING) || !self._output)
		return 0;
	
	// since peer node can't accept any connections directly, 
	// forward the code to the next node. 
	Connection *peer = 0;
	if((peer = self._output->accept(*self._output))){
		// the output has a new stream connected. 
		// we need to create a new PEER node that will handle this new connection. 
		Connection *con = NET_allocConnection(*self.net);
		CON_initPeer(*con, false, con);
		
		// the new connection is technically not connected. 
		// it will become connected once "peer" has become connected. 
		// although in some cases the peer may already be in a connected state
		// so just in case... 
		if(!(peer.state & CON_STATE_CONNECTED))
			con->state = CON_STATE_CONNECTING;
		else
			con->state = CON_STATE_ESTABLISHED;
			
		// set the output to newly accepted peer
		con->_output = peer;
		
		return con;
	}
	return 0;
}

static int _peer_listen(Connection &self, const char *host, uint16_t port){
	// listening means that we are setting up a connection in order to listen for other connections
	// since peer can not directly listen on anything, we just forward the request. 
	if(!self._output || (self.state & CON_STATE_CONNECTED)){
		LOG("You can not listen on this socket.");
		return -1;
	}
	return self._output->listen(*self._output, host, port);
}

void _peer_close(Connection &self){
	// closing a connection means sending out a "close" request down the chain
	// once the connection has been closed, the _output node will set it's 
	// state to CON_STATE_DISCONNECTED. For now we simply go into waiting state. 
	if(!self._output)
		return; 
	
	self._output->close(*self._output);
	self.state = CON_STATE_WAIT_CLOSE;
}


/**
This function packs all data as DATA packet and sends it over to the other peer
if you want to send a custom packet, use sendBlock() instead
this function should only be used to explicitly send data to the node. 
If the node has input connected then it will automatically also read
data from it's input. 
**/
int _peer_send(Connection &self, const char *data, size_t size){
	// calling "send" on peer connection means that we want to send some data
	// therefore we write the data into an input buffer, and then later in the loop
	// we convert this buffer to a CMD_DATA package and send it down the line. 
	return BIO_write(self.in_write, data, size);
}

/** 
Reads a data from the decoded data queue
**/ 
int _peer_recv(Connection &self, char *data, size_t size){
	// when data packets arrive, they are stripped of meta data and the data 
	// is put in the read buffer to be read using this function by the _input node. 
	// this buffer will only contain the contents of received DATA packets. 
	return BIO_read(self.in_read, data, size);
}

/**
SendCommand is supported by nodes that support commands. Our peer node is one of them. 
A SOCKS server for example will support commands as well. If a 
**/
int _peer_send_command(Connection &self, ConnectionMessage cmd, const char *data, size_t size){
	// sending a command means that we want to send the data as an argument to a command
	// this function writes a command packet to the output buffer, which is then sent 
	// down the network in the main loop. inserts a command into the stream. 
	Packet pack; 
	pack.cmd.code = cmd;
	pack.data.resize(size);
	/// hmm? can we be sure that this will never overflow? what if resize() fails?
	memcpy(&pack.data[0], data, size); 
	return BIO_write(self.write_buf, pack.c_ptr(), pack.size());
}

/*** sets up this connection so that it's output is sent to "other"
// instead of the default UDT socket. 
***/
/*
static void _peer_bridge(Connection &self, Connection *other){
	if(!self._output || !self._output->_output)
		return;
	if(other->_input){
		ERROR("You can not bridge to a connection that is a part of another link!");
		return;
	}
	Connection *udt = self._output->_output;
	
	// close the udt connection and connect the output of the 
	// ssl connection to the input of this peer 
	udt->close(*udt); 
	udt->initialized = false;
	
	// now bridge the end of the ssl connection with 
	self._output->bridge(*self._output, other);
	other->_input = self._output;
	//self._output->state = CON_STATE_SSL_HANDSHAKE;
}
*/

/**
This function handles incoming packets received from _output node. 
**/
static void _con_handle_packet(Connection &self, const Packet &packet){
	// if we received DATA packet then data is stored in the buffer that will
	// be read by the _input node using our recv() function. 
	if(packet.cmd.code == CMD_DATA){
		LOG("[con_handle_packet] received DATA of "<<packet.cmd.size);
		BIO_write(self.read_buf, packet.data, packet.cmd.size);
	}
	// this one is sent as a request to make current node connect to a different host
	// the request will originate from _output and the new connection should be 
	// connected to _input. Then all data sent by the input will be sent to the output. 
	else if(packet.cmd.code == RELAY_CONNECT){
		// receiving a connect when we already have an input node is invalid
		// although in the future it may be useful as a way to reuse intermediate peer links. 
		if(self._input){
			ERROR("RELAY_CONNECT received when we already have an _input node.");
			// disconnect
			self.close(self);
			return;
		}
		// data contains a string of format PROTO:IP:PORT
		char tmp[SOCKET_BUF_SIZE];
		memcpy(tmp, packet.data, min((unsigned long)SOCKET_BUF_SIZE, (unsigned long)packet.cmd.size));
		tmp[packet.cmd.size] = 0;
		
		LOG("DATA: "<<tmp);
		
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
		int ret; 
		stringstream err;
		
		LOG("[relay] connecting to: "<<host<<":"<<port);
		
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
		Connection *other = NET_createConnection(*self.net, proto, true);
		Connection *bridge = NET_allocConnection(*self.net);
		CON_initBRIDGE(*bridge, true);
		
		other->connect(*other, host.c_str(), port);
		
		// self<->bridge<->other
		bridge->_input = self;
		self->_input = bridge; 
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
		self.state = CON_STATE_ESTABLISHED; 
	}
}

void _peer_run(Connection &self){
	// receive a complete packet and store it in the packet buffer
	// if no complete packet is available, the function returns 0
	// important: the data may arrive in chunks. so we need to temporarily store 
	// a buffer with previous data and then extend it with new data until we
	// have a valid "packet". A valid packet needs to have valid checksum. 
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	// if we are waiting for connection and connection of the underlying node has been established
	if(self.state & CON_STATE_CONNECTING && self._output && self._output->state & CON_STATE_CONNECTED){
		// copy the hostname 		  
		string str = string("")+string(self._output->host);
		memcpy(self.host, self._output->host, ARRSIZE(self.host));
		self.port = self._output->port;
		// toggle our state to connected as well. 
		self.state = CON_STATE_CONNECTED;
	}
	// handle data flow if we are connected to a peer. 
	if(self.state & CON_STATE_ESTABLISHED){
		// we have an extra buffer where all input data is put
		// this buffer is filled in send() function that is called by someone else
		// all this data belongs in a DATA packet. This data could not have been
		// directly writen to write_buf precisely because it needs to be formatted. 
		while((rc = BIO_read(self.in_write, tmp, SOCKET_BUF_SIZE))>0){
			LOG("[sending data] "<<rc<<" bytes to "<<self.host<<":"<<self.port);
			
			self.sendCommand(self, CMD_DATA, tmp, rc);
		}
		
		/// now we process our write_buf and fill read_buf with data from _ouput
		
		// send unsent data 
		while(self._output && !BIO_eof(self.write_buf)){
			char tmp[SOCKET_BUF_SIZE];
			int rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE);
			self._output->send(*self._output, tmp, rc);
		}
		
		// attempt to receive some data from the underlying connection and decode it
		if(self._output && (rc = self._output->recv(*self._output, tmp, sizeof(tmp)))>0){
			int start = self._recv_buf.size();
			self._recv_buf.resize(self._recv_buf.size()+rc);
			memcpy(&self._recv_buf[start], tmp, rc);
			
			// try to read as many complete packets as possible from the recv buf
			while(self._recv_buf.size()){
				// now we need to check if the packet is complete
				PacketHeader *cmd = (PacketHeader*)&self._recv_buf[0];
				Packet packet;
				if(cmd->size <= self._recv_buf.size()-sizeof(PacketHeader)){
					// check checksum here
					unsigned size = min(ARRSIZE(packet.data), (unsigned long)cmd->size);
					if(size < cmd->size){
						ERROR("Packet exceeds maximum allowed size!");
						return;
					}
					memcpy(packet.data, &self._recv_buf[0]+sizeof(PacketHeader), size);
					memcpy(&packet.cmd, cmd, sizeof(PacketHeader));
					packet.source = &self;
					
					LOG("CON_process: received complete packet at "<<self.host<<":"<<self.port<<" cmd: "<<
						packet.cmd.code<<" datalength: "<<rc);
					//packet.cmd.size<<" recvsize: "<<self._recv_buf.size());
					
					// if we have an output socket then we write the received data directly to that socket
					//LOG(self.bridge);
					_con_handle_packet(self, packet);
					
					self._recv_packs.push_back(packet);
					
					// update the recv_buf to only have the trailing data that has not 
					// yet been decoded. 
					self._recv_buf = vector<char>(
						self._recv_buf.begin()+cmd->size+sizeof(PacketHeader), 
						self._recv_buf.end());
				} else {
					LOG("CON_process: received partial data of "<<rc<< " bytes "<<(self._recv_buf.size()-sizeof(PacketHeader)));
					break;
				}
			}
		}
	}
}


int CON_initPeer(Connection &self, bool client, Connection *ssl){
	CON_init(self);
	
	if(!ssl){
		Connection *ssl = NET_allocConnection(*self.net);
		Connection *udp = NET_allocConnection(*self.net);
		
		if(!ssl || !udp){
			ERROR("init_peer: could not allocate necessary connection objects!");
			return 0;
		}
		
		CON_initSSL(*ssl, client);
		CON_initUDT(*udp, client);
		ssl->_output = udp;
		self._output = ssl;
	} else {
		self._output = ssl;
	}
	
	self.connect = _peer_connect;
	self.accept = _peer_accept;
	self.send = _peer_send;
	self.recv = _peer_recv;
	self.sendCommand = _peer_send_command;
	self.listen = _peer_listen;
	self.run = _peer_run;
	self.bridge = _peer_bridge;
	self.close = _peer_close;
	//self.on_data_received = _peer_on_data_received;
	return 1;
}


