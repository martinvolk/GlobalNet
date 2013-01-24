#include "local.h"

MemoryNode::MemoryNode(){
	
}

MemoryNode::~MemoryNode(){
	
}

int MemoryNode::send(const char *data, size_t maxsize, size_t minsize){
	// write directly to the managed node output in_write buffer
	return BIO_write(in_read, data, maxsize);
}

int MemoryNode::recv(char *data, size_t maxsize, size_t minsize){
	// read directly from the managed node output in_read buffer
	return BIO_read(in_write, data, maxsize);
}

void MemoryNode::run(){
	/*int rc;
	char tmp[SOCKET_BUF_SIZE];
	
	while(!BIO_eof(this->write_buf)){
		if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
			//LOG("LINK: sending "<<rc<<" bytes of data!");
			BIO_write(
		}
	}
	if((rc = this->_output->recv(tmp, sizeof(tmp)))>0){
		//LOG("LINK: received "<<rc<<" bytes of data!");
		BIO_write(this->read_buf, tmp, rc);
	}*/
}
