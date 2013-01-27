/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"


NodeAdapter::NodeAdapter(Network *net, Node *other):Node(net), other(other){
	this->memnode = new MemoryNode(net);
	other->set_output(memnode);
}

NodeAdapter::~NodeAdapter(){
	other->set_output(0);
	delete memnode;
	//other->close();
}

int NodeAdapter::connect(const URL &url){
	this->state = CON_STATE_CONNECTED;
	this->url = url;
	return 1;
}

int NodeAdapter::listen(const URL &url){
	this->state = CON_STATE_LISTENING;
	this->url = url;
	return 1;
}
	
int NodeAdapter::send(const char *data, size_t maxsize, size_t minsize){
	// write directly to the managed node output in_write buffer
	LOG(3,"ADAPTER: send "<<maxsize);
	return memnode->sendOutput(data, maxsize, minsize); 
}

int NodeAdapter::recv(char *data, size_t maxsize, size_t minsize){
	// read directly from the managed node output in_read buffer
	int rc = memnode->recvOutput(data, maxsize, minsize);
	if(rc>0) LOG(3,"ADAPTER: received "<<rc<<" bytes from "<<memnode->url.url());
	return rc;
}


