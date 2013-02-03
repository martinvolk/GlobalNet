#include "local.h"


MemoryNode::MemoryNode(weak_ptr<Network> net, shared_ptr<BufferInterface> buffer):Node(net){
	state = CON_STATE_ESTABLISHED;
	if(buffer)
		m_pBuffer = buffer;
	else
		m_pBuffer = shared_ptr<Buffer>(new Buffer());
}

MemoryNode::~MemoryNode(){
	LOG(3, "MEMORY: deleting!");
}

int MemoryNode::sendOutput(const char *data, size_t size){
	//int rc = BIO_write(read_buf, data, size);
	LOG(3,"MEMNODE: sendOutput, wrote: "<<size<<" bytes.");
	return m_pBuffer->sendOutput(data, size);
}

int MemoryNode::recvOutput(char *data, size_t size, size_t minsize){
	int rc = m_pBuffer->recvOutput(data, size, minsize);
	LOG(3,"MEMNODE: recvOutput, read: "<<rc<<" bytes.");
	return rc;
}
	
int MemoryNode::send(const char *data, size_t size){
	LOG(3,"MEMNODE: send "<<size<<" bytes. "<<url.url());
	return m_pBuffer->send(data, size);
}

int MemoryNode::recv(char *data, size_t size, size_t minsize) const {
	int rc = m_pBuffer->recv(data, size, minsize);
	LOG(3,"MEMNODE: recv, read: "<<rc<<" bytes.");
	return rc;
}

int MemoryNode::connect(const URL &url){
	state = CON_STATE_ESTABLISHED; 
	this->url = url;
	return 1;
}
void MemoryNode::run(){
	
	
}

