/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"


NodeAdapter::NodeAdapter(weak_ptr<Network> net, shared_ptr<BufferInterface> other):Node(net), m_pNode(other){
	
}

NodeAdapter::~NodeAdapter(){
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

int NodeAdapter::recv(char *data, size_t size, size_t minsize) const{
	// swapped around for adapter - we recv from output instead of input. 
	int rc = m_pNode->recvOutput(data, size, minsize);
	if(rc>0) LOG(3,"ADAPTER: received "<<rc<<" bytes.");
	return rc;
}
int NodeAdapter::send(const char *data, size_t size){
	LOG(3,"ADAPTER: send "<<size);
	// swapped around send and sendOutput
	return m_pNode->sendOutput(data, size);
}
int NodeAdapter::recvOutput(char *data, size_t size, size_t minsize) const{
	ERROR("ADAPTER: recvOutput is not supported!");
	return 0;
}
int NodeAdapter::sendOutput(const char *data, size_t size){
	ERROR("ADAPTER: sendOutput is not supported!");
	return 0;
}
/*
NodeAdapter *operator>>(const vector<char> &data, NodeAdapter *node){
	LOG(3,"ADAPTER: send "<<data.size());
	// swapped around send and sendOutput
	node->send(data.data(), data.size());
	return node;
}

NodeAdapter *operator<<(vector<char> &data, NodeAdapter *node){
	// data.size() = minimum bytes to receive
	// data.capacity() = maximum bytes to receive
	size_t max = data.capacity(); 
	size_t min = data.size(); 
	int rc;
	vector<char> tmp(max); 
	if((rc = node->recv(tmp.data(), max, min))>0){
		data.resize(rc); 
		std::copy(tmp.begin(), tmp.end(), data.begin());
	}
	return node;
}
*/

