#include "gclient.h"

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Connection *_bridge_accept(Connection &self){
	ERROR("CON_accept not implemented!");
	return 0;
}

static int _bridge_connect(Connection &self, const char *hostname, uint16_t port){
	ERROR("CON_connect not implemented!");
	return -1;
}

static int _bridge_send(Connection &self, const char *data, size_t size){
	ERROR("CON_send not implemented!");
	return -1;
}
static int _bridge_recv(Connection &self, char *data, size_t size){
	// recv will be called by both of our nodes usually but we will handle 
	// the data flow in the main loop.. 
	return -1;
}

static void _bridge_run(Connection &self){
	// if we are still disconnected and our monitored connection has switched to connected state
	// then we have to notify our input of the change by sending the RELAY_CONNECT_OK command. 
	if(self._output){
		if(!(self.state & CON_STATE_CONNECTED) && self._output->state & CON_STATE_CONNECTED){
			if(self._input){
				self._input->sendCommand(*self._input, RELAY_CONNECT_OK, "", 0);
			}
			self.state = CON_STATE_ESTABLISHED; 
		}
		// if we think we are connected and the other node has gone to disconnected, 
		// then we just disconnect from the peer. All disconnected connections are 
		// cleaned up after all other loops have run next time. 
		if(self.state & CON_STATE_CONNECTED && self._output->state & CON_STATE_INVALID){
			if(self._input){
				self._input->close(*self._input);
			}
			self.state = CON_STATE_DISCONNECTED;
		}
	}
	
	if(self._input && self._output){
		char tmp[SOCKET_BUF_SIZE];
		int rc;
		
		// read data from one end and forward it to the other end and vice versa
		if ((rc = self._input->recv(*self._input, tmp, SOCKET_BUF_SIZE))>0){
			LOG("BRIDGE: received "<<rc<<" bytes from _input");
			self._output->send(*self._output, tmp, rc);
		}
		if ((rc = self._output->recv(*self._output, tmp, SOCKET_BUF_SIZE))>0){
			LOG("BRIDGE: received "<<rc<<" bytes from output!");
			self._input->send(*self._input, tmp, rc);
		}
	}
}
static int _bridge_listen(Connection &self, const char *host, uint16_t port){
	ERROR("CON_listen not implemented!");
	return -1;
}
static void _bridge_peg(Connection &self, Connection *other){
	ERROR("CON_bridge not implemented!");
}
static void _bridge_close(Connection &self){
	ERROR("CON_close not implemented!");
}

void CON_initBRIDGE(Connection &self, bool client){
	CON_init(self, client);
	
	self.connect = _bridge_connect;
	self.send = _bridge_send;
	self.recv = _bridge_recv;
	self.listen = _bridge_listen;
	self.accept = _bridge_accept;
	self.run = _bridge_run;
	self.close = _bridge_close;
}


