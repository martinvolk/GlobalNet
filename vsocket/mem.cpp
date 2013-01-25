#include "local.h"

MemoryNode::MemoryNode(Network *net):Node(net){
	state = CON_STATE_ESTABLISHED;
}

MemoryNode::~MemoryNode(){
	
}

int MemoryNode::sendOutput(const char *data, size_t size, size_t minsize){
	//LOG("MEMNODE: sendOutput "<<size<<" bytes.");
	return BIO_write(read_buf, data, size);
}

int MemoryNode::recvOutput(char *data, size_t size, size_t minsize){
	if(BIO_ctrl_pending(this->write_buf) < minsize || BIO_ctrl_pending(this->write_buf) == 0) return 0;
	int rc = BIO_read(write_buf, data, size);
	//if(rc>0)LOG("MEMNODE: recvOutput "<<size<<" bytes.");
	return rc;
}
	
int MemoryNode::send(const char *data, size_t maxsize, size_t minsize){
	// write directly to the managed node output in_write buffer
	//LOG("MEMNODE: send "<<maxsize<<" bytes. "<<url.url());
	int ret = BIO_write(write_buf, data, maxsize);
	if(_output) _output->send(data, maxsize, minsize);
	run();
	return ret;
}

int MemoryNode::recv(char *data, size_t maxsize, size_t minsize){
	// read directly from the managed node output in_read buffer
	run();
	if(BIO_ctrl_pending(this->read_buf) < minsize || BIO_ctrl_pending(this->read_buf) == 0) return 0;
	int rc = BIO_read(read_buf, data, maxsize);
	if(_output) rc = _output->recv(data, maxsize, minsize);
	if(rc > 0) LOG("MEMNODE: recv "<<rc<<" bytes.");
	return rc;
}

int MemoryNode::connect(const URL &url){
	state = CON_STATE_ESTABLISHED; 
	this->url = url;
	return 1;
}
void MemoryNode::run(){
	int rc;
	char tmp[SOCKET_BUF_SIZE];
	/*
	if(_output){
		if(BIO_ctrl_pending(write_buf)>0){
			if((rc = BIO_read(write_buf, tmp, SOCKET_BUF_SIZE))>0)
				_output->send(tmp, rc);
		}
		if((rc = _output->recv(tmp, SOCKET_BUF_SIZE))>0){
			//LOG("LINK: sending "<<rc<<" bytes of data!");
			BIO_write(read_buf, tmp, rc);
		}
		_output->run();
	}*/
}
