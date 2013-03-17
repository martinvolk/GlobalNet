/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************/

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

