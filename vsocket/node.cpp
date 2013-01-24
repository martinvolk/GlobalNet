/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Node * Node::accept(){
	ERROR("CON_accept not implemented!");
	return 0;
}

int Node::connect(const char *hostname, uint16_t port){
	ERROR("CON_connect not implemented!");
	return -1;
}

int Node::send(const char *data, size_t size, size_t minsize){
	ERROR("CON_send not implemented!");
	return -1;
}
int Node::recv(char *data, size_t size, size_t minsize){
	ERROR("CON_recv not implemented!");
	return -1;
}


int Node::sendCommand(NodeMessage msg, const char *data, size_t size){
	// the default behavior is to simply pass the command down the line
	if(this->_output)
		this->_output->sendCommand(msg, data, size);
	return 1;
}

int Node::sendCommand(const Packet &pack){
	// the default behavior is to simply pass the command down the line
	if(this->_output)
		this->_output->sendCommand(pack);
	return 1;
}

int Node::recvCommand(Packet *dst){
	// only used by Peer. 
	//ERROR("CON: call to recvCommand(): NOT IMPLEMENTED!"); 
	return 0;
}

void Node::run(){
	if(_output)
		_output->run();
}
int Node::listen(const char *host, uint16_t port){
	ERROR("CON_listen not implemented!");
	return -1;
}
void Node::peg(Node *other){
	ERROR("CON_bridge not implemented!");
}

void Node::close(){
	ERROR("CONNECTION: close() has to be implemented!");
}


Node *Node::createNode(const char *name){
	if(strcmp(name, "peer")== 0){
		return new VSLNode(0);
	}
	else if(strcmp(name, "tcp")==0){
		return new TCPNode();
	}
	else if(strcmp(name, "udt")==0){
		return new UDTNode();
	}
	else if(strcmp(name, "ssl")==0){
		return new SSLNode();
	}
	else if(strcmp(name, "socks")==0){
		return new SocksNode();
	}
	else{
		ERROR("Unknown socket type '"<<name<<"'");
	}
	return 0;
}

Node::Node(){
	this->_output = 0;
	this->_input = 0;
	this->type = NODE_NONE;
	
	/* set up the memory-buffer BIOs */
	this->read_buf = BIO_new(BIO_s_mem());
	this->write_buf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(this->read_buf, -1);
	BIO_set_mem_eof_return(this->write_buf, -1);
	
	this->in_read = BIO_new(BIO_s_mem());
	this->in_write = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(this->in_read, -1);
	BIO_set_mem_eof_return(this->in_write, -1);
	
	this->state = CON_STATE_INITIALIZED;
}

void Node::set_output(Node *other){
	if(this->_output) delete _output;
	this->_output = other;
	if(other)
		other->set_input(this);
}
void Node::set_input(Node *other){ 
	this->_input = other;
	//other->set_output(this);
}
Node* Node::get_output(){
	return this->_output;
}
Node* Node::get_input(){
	return this->_input;
}

void Node::set_option(const string &opt, const string &val){
	options[opt] = val;
}

bool Node::get_option(const string &opt, string &res){
	if(options.find(opt) != options.end()){
		res = options[opt];
		return true;
	}
	return false;
}

set<long> deleted;
Node::~Node(){
	//LOG("NODE: deleting "<<this<<": "<<this->host<<":"<<this->port);
	if(deleted.find((long)this) != deleted.end()){
		cout<<"DOUBLE FREE!"<<endl;
	}
	deleted.insert((long)this);
	this->state = CON_STATE_UNINITIALIZED;
	
	if(read_buf) BIO_free(this->read_buf);
	if(write_buf) BIO_free(this->write_buf);
	if(in_read) BIO_free(this->in_read);
	if(in_write) BIO_free(this->in_write);
	
	read_buf = write_buf = in_read = in_write = 0;
	
	/*if(this->_output && this->_output != this){
		if(this->_output->_input == this)
			this->_output->_input = 0;
		if(this->_output->_output == this)
			this->_output->_output = 0;
		delete _output;
	}*/
	/*
	if(this->_input && this->_input != this){
		if(this->_input->_input == this)
			this->_input->_input = 0;
		if(this->_input->_output == this)
			this->_input->_output = 0;
		delete _input;
	}*/
	
	this->_output = 0;
	this->_input = 0;
	
}

NodeAdapter::NodeAdapter(Node *other):other(other){
	this->memnode = new MemoryNode();
	other->set_output(memnode);
}

NodeAdapter::~NodeAdapter(){
	
}

int NodeAdapter::connect(const char *host, uint16_t port){
	this->state = CON_STATE_CONNECTED;
	this->host = host;
	this->port = port;
	return 1;
}

int NodeAdapter::listen(const char *host, uint16_t port){
	this->state = CON_STATE_LISTENING;
	this->host = host;
	this->port = port;
	return 1;
}
	
int NodeAdapter::send(const char *data, size_t maxsize, size_t minsize){
	// write directly to the managed node output in_write buffer
	return memnode->sendOutput(data, maxsize, minsize); 
}

int NodeAdapter::recv(char *data, size_t maxsize, size_t minsize){
	// read directly from the managed node output in_read buffer
	return memnode->recvOutput(data, maxsize, minsize);
}

