/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "local.h"

BridgeNode::BridgeNode(){
	type = NODE_BRIDGE;
}

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Node *BridgeNode::accept(){
	ERROR("CON_accept not implemented!");
	return 0;
}

int BridgeNode::connect(const char *hostname, uint16_t port){
	ERROR("CON_connect not implemented!");
	return -1;
}

int BridgeNode::send(const char *data, size_t size){
	ERROR("CON_send not implemented!");
	return -1;
}
int BridgeNode::recv(char *data, size_t size){
	// recv will be called by both of our nodes usually but we will handle 
	// the data flow in the main loop.. 
	return -1;
}

void BridgeNode::run(){
	Node::run();
	
	// if we are still disconnected and our monitored connection has switched to connected state
	// then we have to notify our input of the change by sending the RELAY_CONNECT_OK command. 
	if(this->_output){
		if(!(this->state & CON_STATE_CONNECTED) && this->_output->state & CON_STATE_CONNECTED){
			if(this->_input){
				this->_input->sendCommand(RELAY_CONNECT_OK, "", 0);
			}
			LOG("BRIDGE: connection established on the remote end!");
			this->state = CON_STATE_ESTABLISHED; 
		}
		// if we think we are connected and the other node has gone to disconnected, 
		// then we just disconnect from the peer. All disconnected connections are 
		// cleaned up after all other loops have run next time. 
		if(this->state & CON_STATE_CONNECTED && this->_output->state & CON_STATE_INVALID){
			LOG("BRIDGE: connection _output disconnected!");
			//this->_input = 0;
			if(this->_input){
				// we send relay disconnect because we want to be able to save the connection on the remote 
				// end. So simply doing close() here would be inappropriate because the client may want
				// to reuse the already opened connection to the relay (us). 
				this->_input->sendCommand(RELAY_DISCONNECT, "", 0);
			}
			this->state = CON_STATE_DISCONNECTED;
		}
		if(this->state & CON_STATE_CONNECTED && this->_input->state & CON_STATE_INVALID){
			if(this->_output){
				this->_output->close();
			}
			LOG("BRIDGE: connection _input disconnected!");
			this->state = CON_STATE_DISCONNECTED;
		}
	}
	
	if(this->_input && this->_output){
		char tmp[SOCKET_BUF_SIZE];
		int rc;
		
		// read data from one end and forward it to the other end and vice versa
		if ((rc = this->_input->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG("BRIDGE: received "<<rc<<" bytes from _input");
			this->_output->send(tmp, rc);
		}
		if ((rc = this->_output->recv(tmp, SOCKET_BUF_SIZE))>0){
			LOG("BRIDGE: received "<<rc<<" bytes from output!");
			this->_input->send(tmp, rc);
		}
	}
}
int BridgeNode::listen(const char *host, uint16_t port){
	ERROR("CON_listen not implemented!");
	return -1;
}
void BridgeNode::close(){
	ERROR("CON_close not implemented!");
}



