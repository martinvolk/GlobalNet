/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"

/** 
A link is a chain of n nodes that go through different hosts to a destination
- works exactly like any other connection. 
- connect() takes an encoded string as argument that encodes the path. 
- supports remote listening (useful for rendezvous nodes)
**/ 
/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Connection *_lnk_accept(Connection &self){
	ERROR("[link] accept not implemented at the moment!");
	return 0; 
}

static int _lnk_connect(Connection &self, const char *hostname, uint16_t port){
	// calling connect on a link can have several meanings. If the host starts
	// with "peer:" the link will connect to a peer. If the link is already 
	// connected to something then it will issue sendCommand and try to 
	// connect from the already connected host to the next one. 
	
	// parse the address
	string str = string(hostname);
	vector<string> tokens;
	tokenize(str, ":",tokens);
	string proto = "";
	string host = "";
	if(tokens.size() == 3){
		proto = tokens[0];
		host = tokens[1];
		port = atoi(tokens[2].c_str());
	} else {
		ERROR("LINK URL FORMAT NOT SUPPORTED! PLEASE USE proto:host:port! "<<hostname);
	}
	
	if(proto.compare("tcp")==0){
		LOG("LINK: issuing remote connect command: connecting to "<<hostname);
		self._output->sendCommand(*self._output, RELAY_CONNECT, hostname, strlen(hostname));
	}
	else if(proto.compare("peer")==0){
		LOG("LINK: connecting to new node: "<<host<<":"<<port);
		// peg a peer on top of the current connection and issue a connect
		Connection *peer = NET_allocConnection(*self.net);
		CON_initPeer(*peer);
		
		if(self._output)
			peer->peg(*peer, self._output);
		peer->connect(*peer, host.c_str(), port);
		self._output = peer;
	}
	
	return 1;
}

static int _lnk_send(Connection &self, const char *data, size_t size){
	// we place the data in the link buffer and send it out later in the 
	// main loop. 
	LOG("LINK: send(): "<<size<<" bytes!");
	return BIO_write(self.write_buf, data, size);
}
static int _lnk_recv(Connection &self, char *data, size_t size){
	return BIO_read(self.read_buf, data, size);
}

static int _lnk_send_command(Connection &self, ConnectionMessage cmd, const char *data, size_t size){
	ERROR("[link] send command not implemented!");
	return -1;
}

static void _lnk_run(Connection &self){
	// sending data to the link simply means that we are sending data through
	// the chain of connections. So we can just use the next nodes send 
	// function to encode the data and get it out to it's destination. 
	int rc;
	char tmp[SOCKET_BUF_SIZE];
	
	// if the link is now connected
	if((self.state & CON_STATE_INITIALIZED) && self._output && self._output->state & CON_STATE_CONNECTED){
		LOG("[link] link connected!");
		
		memcpy(self.host, self._output->host, ARRSIZE(self.host));
		self.port = self._output->port;
		
		self.state = CON_STATE_ESTABLISHED;
	}
	
	if(self.state & CON_STATE_CONNECTED){
		// send/recv data
		while(!BIO_eof(self.write_buf)){
			if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0){
				LOG("LINK: sending "<<rc<<" bytes of data!");
				self._output->send(*self._output, tmp, rc);
			}
		}
		if((rc = self._output->recv(*self._output, tmp, sizeof(tmp)))>0){
			LOG("LINK: received "<<rc<<" bytes of data!");
			BIO_write(self.read_buf, tmp, rc);
		}
	}
	
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(self._output && self._output->state & CON_STATE_DISCONNECTED){
		LOG("LINK: underlying connection lost. Disconnected!");
		self.state = CON_STATE_DISCONNECTED;
	}
}
static int _lnk_listen(Connection &self, const char *host, uint16_t port){
	ERROR("[link] listen not implemented!");
	return -1;
}
static void _lnk_peg(Connection &self, Connection *other){
	ERROR("[link] peg not implemented. It is not recommended to peg links.");
}

static void _lnk_close(Connection &self){
	if(!self._output){
		self.state = CON_STATE_DISCONNECTED;
		return;
	}
	
	while(!BIO_eof(self.write_buf)){
		char tmp[SOCKET_BUF_SIZE];
		int rc;
		if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0){
			self._output->send(*self._output, tmp, rc);
		}
	}
	self._output->close(*self._output);
	self.state = CON_STATE_WAIT_CLOSE;
}

void CON_initLINK(Connection &self){ 
	CON_init(self);  
	
	self.type = NODE_LINK;
	
	self.connect = _lnk_connect;
	self.send = _lnk_send;
	self.recv = _lnk_recv;
	self.sendCommand = _lnk_send_command;
	self.listen = _lnk_listen;
	self.accept = _lnk_accept;
	self.run = _lnk_run;
	self.peg = _lnk_peg;
	self.close = _lnk_close;
	
	self.state = CON_STATE_INITIALIZED;
}


