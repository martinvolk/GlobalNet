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

/** 
A bridge connects two outgoing nodes and reads data from one and forwards
it to the other - and vice versa. 
**/
BridgeNode::BridgeNode(weak_ptr<Network> net, unique_ptr<Node> node1, unique_ptr<Node> node2):
	Node(net), m_pNodeOne(move(node1)), m_pNodeTwo(move(node2)){
	type = NODE_BRIDGE;
}

BridgeNode::~BridgeNode(){
	LOG(3, "BRIDGE: deleting.");
}

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
unique_ptr<Node> BridgeNode::accept(){
	ERROR("CON_accept not implemented!");
	return unique_ptr<Node>();
}

int BridgeNode::connect(const URL &url){
	ERROR("CON_connect not implemented!");
	return -1;
}

int BridgeNode::send(const char *data, size_t size){
	ERROR("BRIDGE: send not implemented!");
	return -1;
}
int BridgeNode::recv(char *data, size_t size, size_t minsize) const{
	ERROR("BRIDGE: recv not implemented!");
	// recv will be called by both of our nodes usually but we will handle 
	// the data flow in the main loop.. 
	return -1;
}

void BridgeNode::run(){
	if(this->m_pNodeOne->state & CON_STATE_ESTABLISHED && 
			this->m_pNodeTwo->state & CON_STATE_ESTABLISHED){
		this->state = CON_STATE_ESTABLISHED;
	}
	
	this->m_pNodeOne->run();
	this->m_pNodeTwo->run();
	
	if(this->state & CON_STATE_CONNECTED){
		char tmp[SOCKET_BUF_SIZE];
		int rc;
		
		if(this->m_pNodeOne->state & CON_STATE_DISCONNECTED){
			this->m_pNodeTwo->close();
			this->state = CON_STATE_DISCONNECTED;
			return;
		}
		else if(this->m_pNodeTwo->state & CON_STATE_DISCONNECTED){
			this->m_pNodeOne->close();
			this->state = CON_STATE_DISCONNECTED;
			return;
		}
	
		// read data from one end and forward it to the other end and vice versa
		if ((rc = this->m_pNodeOne->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG(3, "BRIDGE: received "<<rc<<" bytes from m_pNodeOne");
			//LOG(hexencode(tmp, rc));
			this->m_pNodeTwo->send(tmp, rc);
		}
		if ((rc = this->m_pNodeTwo->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG(3, "BRIDGE: received "<<rc<<" bytes from output!");
			//LOG(hexencode(tmp, rc));
			this->m_pNodeOne->send(tmp, rc);
		}
	}
}
int BridgeNode::listen(const URL &url){
	ERROR("CON_listen not implemented!");
	return -1;
}
void BridgeNode::close(){
	this->m_pNodeTwo->close();
	this->m_pNodeOne->close();
	this->state = CON_STATE_DISCONNECTED;
}



