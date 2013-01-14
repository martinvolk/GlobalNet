#include "gclient.h"

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
	ERROR("CON_connect not implemented!");
	return -1;
}

static int _lnk_send(Connection &self, const char *data, size_t size){
	// we place the data in the link buffer and send it out later in the 
	// main loop. 
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
	if(!(self.state & CON_STATE_CONNECTING) && self._output->state & CON_STATE_CONNECTED){
		LOG("[link] link connected!");
		
		memcpy(self.host, self._output->host, ARRSIZE(self.host));
		self.port = self._output->port;
		
		self.state = CON_STATE_ESTABLISHED;
	}
	
	if(self.state & CON_STATE_CONNECTED){
		// send/recv data
		while(!BIO_eof(self.write_buf)){
			if((rc = BIO_read(self.write_buf, tmp, SOCKET_BUF_SIZE))>0){
				//LOG("UDT: sending "<<rc<<" bytes of data!");
				UDT::send(self.socket, tmp, rc, 0);
			}
		}
		if((rc = UDT::recv(self.socket, tmp, sizeof(tmp), 0))>0){
			//LOG("UDT: received "<<rc<<" bytes of data!");
			BIO_write(self.read_buf, tmp, rc);
		}
		// if disconnected
		if (UDT::ERROR == rc){
			if(self.is_client && self.state != CON_STATE_LISTENING && UDT::getlasterror().getErrorCode() == 2002){
				LOG("UDT: " << (&self) << " "<<self.host<<":"<<self.port<<" "<<rc <<": "<< UDT::getlasterror().getErrorMessage());
				UDT::close(self.socket);
				self.state = CON_STATE_DISCONNECTED;
			}
		}
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
	// signal a close to the remote connection
	if(self._output)
		self._output->close(*self._output);
		
	self.state = CON_STATE_WAIT_CLOSE;
}

void CON_initLINK(Connection &self, bool client){ 
	CON_init(self, true);
	
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


