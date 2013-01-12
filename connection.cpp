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

static int _con_recv_block(Connection &self, Packet &pack){
	ERROR("CON_recvBlock not implemented!");
	return -1;
}

static int _con_send_block(Connection &self, const Packet &pack){
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
static void _con_bridge(Connection &self, Connection *other){
	ERROR("CON_bridge not implemented!");
}
static void _con_close(Connection &self){
	ERROR("CON_close not implemented!");
}

static void _con_on_data_received(Connection &self, const char *data, size_t size){
	ERROR("CON_data_received not implemented!");
}

void CON_init(Connection &self, bool client){
	self.ssl = 0;
	self.ctx = 0;
	self._next = 0;
	self._prev = 0;
	self.is_client = client;
	
	/* set up the memory-buffer BIOs */
	self.read_buf = BIO_new(BIO_s_mem());
	self.write_buf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(self.read_buf, -1);
	BIO_set_mem_eof_return(self.write_buf, -1);
	
	self.connect = _con_connect;
	self.send = _con_send;
	self.recv = _con_recv;
	self.recvBlock = _con_recv_block;
	self.sendBlock = _con_send_block;
	self.listen = _con_listen;
	self.accept = _con_accept;
	self.run = _con_run;
	self.bridge = _con_bridge;
	self.close = _con_close;
	self.on_data_received = _con_on_data_received;
}

void CON_shutdown(Connection &self){
	
}

