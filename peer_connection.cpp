#include "gclient.h"

struct peer_data_t{
	Connection *peer;
};

int _peer_connect(Connection *self, const char *hostname, uint16_t port){ 
	if(self->state == CON_STATE_ESTABLISHED){
		cout<<"CON_connect: connection is already initialized. Please call CON_close() before establishing a new one!"<<endl;
		return -1;
	}
	// if bridged then we need to send a relay message and connect ssl after that
	if(self->_prev){
		// tell the remote end of the socket to connect instead of us
		
		
		// connection will be established once the relay responds with RELAY_CONNECT_OK
	} else {
		// establish a direct connection
		if(!self->_next->connect(self->_next, hostname, port)){
			LOG("[error] error connecting to "<<hostname<<":"<<port);
		} 
	}
	
	return 1;
}

Connection *_peer_accept(Connection *self){
	if(!self->_next){
		LOG("[peer] can not call accept() when no network layer!");
		return 0;
	}
		
	/// accept connections on the server socket 
	Connection *con = new Connection();
	CON_initPeer(con, false);
	
	if(!(con->_next = self->_next->accept(self->_next))){
		delete con;
		return 0;
	}
	//LOG("[peer] accepted new connection!");
	con->state = CON_STATE_DISCONNECTED; // will be changed once SSL negotiates
	
	return con;
}

static int _peer_listen(Connection *self, const char *host, uint16_t port){
	if(self->is_client && !self->_next){
		ERROR("[peer] can not listen on "<<host<<":"<<port<<": method not supported!");
		return -1;
	}
	return self->_next->listen(self->_next, host, port);
}

void _peer_close(Connection *self){
	if(self->_next)
		self->_next->close(self->_next);
	self->state = CON_STATE_CLOSE_PENDING;
}


/** 
This function packs all data as DATA packet and sends it over to the other peer
if you want to send a custom packet, use sendBlock() instead
**/
int _peer_send(Connection *self, const char *data, size_t size){
	// reception is handled automatically in handle_packet
	LOG("[sending to next] "<<size<<" bytes to "<<self->_next->host<<":"<<self->_next->port);
	Packet pack;
	pack.cmd.code = CMD_DATA;
	pack.data.resize(size);
	memcpy(&pack.data[0], data, size);
	return BIO_write(self->write_buf, pack.c_ptr(), pack.size());
}
/** 
Attempts to receive a packet. 
Note: do not ever call CON_recv() directly if you are using this function
**/ 
int _peer_recv(Connection *self, char *data, size_t size){
	ERROR("Peer recv() not implemented. Use recvBlock instead!");
	return -1;
}

/*** sets up this connection so that it's output is sent to "other"
// instead of the default UDT socket. 
***/
static void _peer_bridge(Connection *self, Connection *other){
	if(!self->_next || !self->_next->_next)
		return;
	if(other->_prev){
		ERROR("You can not bridge to a connection that is a part of another link!");
		return;
	}
	Connection *udt = self->_next->_next;
	
	// close the udt connection and connect the output of the 
	// ssl connection to the input of this peer 
	udt->close(udt); 
	delete udt;
	
	// now bridge the end of the ssl connection with 
	self->_next->bridge(self->_next, other);
	other->_prev = self->_next;
	//self->_next->state = CON_STATE_SSL_HANDSHAKE;
}


static void _con_send_error(Connection *self, ConnectionError err, const string &description){
	Packet pack;
	pack.cmd.code = RELAY_ERROR;
	pack.data.resize(description.size()+sizeof(ConnectionError));
	memcpy(&pack.data[0], &err, sizeof(ConnectionError));
	memcpy(&pack.data[sizeof(ConnectionError)], &description[0], description.length());
	BIO_write(self->write_buf, pack.c_ptr(), pack.size());
}
static void _con_send_message(Connection *self, ConnectionMessage msg){
	Packet pack;
	pack.cmd.code = msg;
	self->_next->send(self, pack.c_ptr(), pack.size());
}

static void _con_handle_packet(Connection *self, const Packet &packet){
	/// forward data packets if we are connected to other sockets
	if(packet.cmd.code == CMD_DATA && self->_prev){
		self->_prev->send(self->_prev, &packet.data[0], packet.data.size()); 
		LOG("[bridge] forwarded "<<packet.data.size()<<" bytes to external socket!");
	}
	// if we have a listener socket then we write the data to it's input buffer as well
	else if(packet.cmd.code == CMD_DATA && self->_prev){
		self->_prev->on_data_received(self->_prev, &packet.data[0], packet.data.size());
		LOG("[bridge] forwarding "<<packet.data.size()<<" bytes to internal socket "<<
				self->_prev->host<<":"<<self->_prev->port);
	}
	
	/// we have received a request to extend our connection to another host
	else if(packet.cmd.code == RELAY_CONNECT){
		if(self->_prev){
			_con_send_error(self, REL_ERR_CON_FAILED, "[relay] can not connect remote end because it is already connected.");
			return;
		}
		string str = string(packet.data.begin(), packet.data.end());
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
		if(proto == "udt"){
			Connection *c = self->_prev = new Connection();
			CON_initUDT(c);
			
			if((ret = c->connect(c, host.c_str(), port)) > 0){
				_con_send_message(self, RELAY_CONNECT_OK);
			} else {
				// failed
				err<<"Socket connection failed "<<host<<":"<<port;
				_con_send_error(self, REL_ERR_CON_FAILED, err.str());
			}
		} else if(proto == "tcp"){
			Connection *c = self->_prev = new Connection();
			CON_initTCP(c);
			
			if((ret = c->connect(c, host.c_str(), port)) > 0){
				_con_send_message(self, RELAY_CONNECT_OK);
			} else{
				err<<"Socket connection failed "<<host<<":"<<port;
				_con_send_error(self, REL_ERR_CON_FAILED, err.str());
			}
		}
	}
	else if(packet.cmd.code == RELAY_CONNECT_OK){
		// signal to the bridged connection that it can start sending data
		if(self->_prev){
			LOG("[connection] relay connection succeeded. Now connected through the relay! ");
			self->_prev->state = CON_STATE_ESTABLISHED;
		} else {
			LOG("[error] received RELAY_CONNECT_OK, but connection is not bridged!");
		}
	}
	else if(packet.cmd.code == RELAY_ERROR){
		if(packet.data.size() > sizeof(ConnectionError)){
			ConnectionError err;
			
			LOG("[error] "+string(packet.data.begin()+sizeof(ConnectionError), packet.data.end()));
			memcpy(&err, &packet.data[0], sizeof(ConnectionError));
			
			if(err == REL_ERR_CON_FAILED){
				self->state = CON_STATE_DISCONNECTED;
			}
		}
	}
	else if(packet.cmd.code == RELAY_DISCONNECT){
		self->close(self);
	}
}

int _peer_recv_block(Connection *self, Packet &block){
	if(self->_recv_packs.size()>0){
		block = self->_recv_packs.front();
		self->_recv_packs.pop_front();
		return 1;
	}
	return -1;
}

int _peer_send_block(Connection *self, const Packet &block){
	if(self->_next){
		Packet pack = block;
		return self->_next->send(self->_next, pack.c_ptr(), pack.size());
	}
	return -1;
}

void _peer_run(Connection *self){
	// receive a complete packet and store it in the packet buffer
	// if no complete packet is available, the function returns 0
	// important: the data may arrive in chunks. so we need to temporarily store 
	// a buffer with previous data and then extend it with new data until we
	// have a valid "packet". A valid packet needs to have valid checksum. 
	char tmp[SOCKET_BUF_SIZE];
	int rc;
	
	//LOG("[peer] run "<<self->host<<":"<<self->port);
	if(self->_next)
		self->_next->run(self->_next);
	
	if(self->_next && self->_next->state == CON_STATE_ESTABLISHED)
		self->state = CON_STATE_ESTABLISHED;
		
	/// if we have a connection to a peer
	if(self->state == CON_STATE_ESTABLISHED){
		/// if we have an external socket then read data from it and send it over as data packet to the other peer
		if(self->_prev){
			char tmp[SOCKET_BUF_SIZE];
			int ss = self->_prev->recv(self->_prev, tmp, SOCKET_BUF_SIZE);
		
			if(ss>0){
				LOG("[bridge] peer_process: recieved "<<ss<<" bytes from external connection");
				Packet pack;
				pack.cmd.code = CMD_DATA;
				pack.cmd.data_length = ss;
				pack.data.resize(ss);
				memcpy(&pack.data[0], tmp, ss);
				vector<char> buf;
				pack.toVec(buf);
				// forward the data to the connection higher up in queue
				self->_next->send(self->_next, &buf[0], buf.size());
			}
		} 
		
		/// send all unsent data
		while(self->_next && !BIO_eof(self->write_buf)){
			char tmp[SOCKET_BUF_SIZE];
			int rc = BIO_read(self->write_buf, tmp, SOCKET_BUF_SIZE);
			self->_next->send(self->_next, tmp, rc);
		}
		
		// attempt to receive some data from the underlying connection
		if(self->_next && (rc = self->_next->recv(self->_next, tmp, sizeof(tmp)))>0){
			int start = self->_recv_buf.size();
			self->_recv_buf.resize(self->_recv_buf.size()+rc);
			memcpy(&self->_recv_buf[start], tmp, rc);
			
			// try to read as many complete packets as possible from the recv buf
			while(self->_recv_buf.size()){
				// now we need to check if the packet is complete
				Command *cmd = (Command*)&self->_recv_buf[0];
				Packet packet;
				if(cmd->data_length <= self->_recv_buf.size()-sizeof(Command)){
					// check checksum here
					if(cmd->data_length == self->_recv_buf.size()-sizeof(Command))
						packet.data = vector<char>(self->_recv_buf.begin()+sizeof(Command), self->_recv_buf.end());
					else
						packet.data = vector<char>(self->_recv_buf.begin()+sizeof(Command), self->_recv_buf.begin()+cmd->data_length+sizeof(Command));
					
					memcpy(&packet.cmd, cmd, sizeof(Command));
					packet.source = self;
					
					LOG("CON_process: received complete packet at "<<self->host<<":"<<self->port<<" cmd: "<<
						packet.cmd.code<<" datalength: "<<rc);
					//packet.cmd.data_length<<" recvsize: "<<self->_recv_buf.size());
					
					// if we have an output socket then we write the received data directly to that socket
					//LOG(self->bridge);
					_con_handle_packet(self, packet);
					
					self->_recv_packs.push_back(packet);
					
					// update the recv_buf to only have the trailing data that has not 
					// yet been decoded. 
					self->_recv_buf = vector<char>(
						self->_recv_buf.begin()+cmd->data_length+sizeof(Command), 
						self->_recv_buf.end());
				} else {
					LOG("CON_process: received partial data of "<<rc<< " bytes "<<(self->_recv_buf.size()-sizeof(Command)));
					break;
				}
			}
		}
	}
}


int CON_initPeer(Connection *self, bool client){
	CON_init(self);
	
	Connection *ssl = new Connection();
	Connection *udp = new Connection();
	CON_initSSL(ssl, client);
	CON_initUDT(udp, client);
	ssl->_next = udp;
	self->_next = ssl;
	
	self->connect = _peer_connect;
	self->accept = _peer_accept;
	self->send = _peer_send;
	self->recv = _peer_recv;
	self->recvBlock = _peer_recv_block;
	self->sendBlock = _peer_send_block;
	self->listen = _peer_listen;
	self->run = _peer_run;
	self->bridge = _peer_bridge;
	self->close = _peer_close;
	//self->on_data_received = _peer_on_data_received;
	return 1;
}


