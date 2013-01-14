#include "gclient.h"

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Connection *_con_accept(Connection &self){
	ERROR("CON_accept not implemented!");
	return 0;
}

static int _con_connect(Connection &self, const char *hostname, uint16_t port){
	ERROR("CON_connect not implemented!");
	return -1;
}

static int _con_send(Connection &self, const char *data, size_t size){
	ERROR("CON_send not implemented!");
	return -1;
}
static int _con_recv(Connection &self, char *data, size_t size){
	ERROR("CON_recv not implemented!");
	return -1;
}


static int _con_send_command(Connection &self, ConnectionMessage msg, const char *data, size_t size){
	ERROR("CON_writeBlock not implemented!");
	return -1;
}

static void _con_run(Connection &self){
	ERROR("CON_run not implemented!");
}
static int _con_listen(Connection &self, const char *host, uint16_t port){
	ERROR("CON_listen not implemented!");
	return -1;
}
static void _con_peg(Connection &self, Connection *other){
	ERROR("CON_bridge not implemented!");
}
static void _con_close(Connection &self){
	ERROR("CON_close not implemented!");
}

void CON_init(Connection &self, bool client){
	self.ssl = 0;
	self.ctx = 0;
	self._output = 0;
	self._input = 0;
	self.is_client = client;
	
	/* set up the memory-buffer BIOs */
	self.read_buf = BIO_new(BIO_s_mem());
	self.write_buf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(self.read_buf, -1);
	BIO_set_mem_eof_return(self.write_buf, -1);
	
	self.in_read = BIO_new(BIO_s_mem());
	self.in_write = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(self.in_read, -1);
	BIO_set_mem_eof_return(self.in_write, -1);
	
	self.connect = _con_connect;
	self.send = _con_send;
	self.recv = _con_recv;
	self.sendCommand = _con_send_command;
	self.listen = _con_listen;
	self.accept = _con_accept;
	self.run = _con_run;
	self.peg = _con_peg;
	self.close = _con_close;
	
	self.state = CON_STATE_INITIALIZED;
}

void CON_shutdown(Connection &self){
	LOG("[connection] closing "<<self.host<<":"<<self.port);
	
	if(self.close)
		self.close(self);
		
	if(self.ssl){
		SSL_shutdown(self.ssl);
		SSL_free(self.ssl);
		if(self.ctx)
			SSL_CTX_free(self.ctx);
	}
	if(self._output){
		self._output->_input = 0;
		NET_free(self._output);
	}
	if(self._input){
		self._input->_output = 0;
		NET_free(self._input);
	}
	
	if(self.socket)
		close(self.socket);
	
	self.ssl = 0;
	self.ctx = 0;
	self._output = 0;
	self._input = 0;
	self.socket = 0;
}
