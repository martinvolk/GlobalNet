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
A link is a chain of n nodes that go through different hosts to a destination
- works exactly like any other connection. 
- connect() takes an encoded string as argument that encodes the path. 
- supports remote listening (useful for rendezvous nodes)
**/ 
/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
Node *LinkNode::accept(){
	ERROR("[link] accept not implemented at the moment!");
	return 0; 
}


LinkNode::LinkNode(shared_ptr<Network> net):Node(net){ 
	this->type = NODE_LINK;
	this->state = CON_STATE_INITIALIZED;
}

LinkNode::~LinkNode(){
	this->close();
}

int LinkNode::connect(const URL &url){
	// calling connect on a link can have several meanings. If the host starts
	// with "peer:" the link will connect to a peer. If the link is already 
	// connected to something then it will issue sendCommand and try to 
	// connect from the already connected host to the next one. 
	/*
	// parse the address
	string str = string(url.host());
	vector<string> tokens;
	tokenize(str, ":",tokens);
	string proto = "";
	string host = "";
	if(tokens.size() == 3){
		proto = tokens[0];
		host = tokens[1];
		port = atoi(tokens[2].c_str());
	} else {
		ERROR("LINK URL FORMAT NOT SUPPORTED! PLEASE USE proto:host:port! "<<url.host());
	}
	
	// connect the nodes appropriately.
	if(proto.compare("tcp")==0){
		// do nothing since TCP will simply use sendData()
		LOG("LINK: issuing remote connect to: "<<host<<":"<<port);
		this->_output->sendCommand(RELAY_CONNECT, url.host().c_str(), url.host().length());
	}
	else if(proto.compare("peer")==0){
		LOG("LINK: connecting to new node: "<<host<<":"<<port);
		
		// add a new decoder node and connect it's output to the input of the current node
		VSLNode *peer = new VSLNode();
		if(this->_output){
			// issue a remote relay connect
			this->_output->sendCommand(RELAY_CONNECT, url.host().c_str(), url.host().length());
			
			this->_output->_input = peer;
			peer->setOutput(this->_output);
			this->_output = peer;
		} else {
			this->_output = peer;
			peer->_input = this;
			peer->connect(url);
		}
	}
	*/
	return 1;
}

int LinkNode::send(const char *data, size_t size, size_t minsize){
	// we place the data in the link buffer and send it out later in the 
	// main loop. 
	//LOG("LINK: send(): "<<size<<" bytes!");
	if(this->state & CON_STATE_INVALID) return -1;
	return BIO_write(this->write_buf, data, size);
}

int LinkNode::recv(char *data, size_t size, size_t minsize){
	if(this->state & CON_STATE_INVALID) return -1;
	if(BIO_eof(this->read_buf) || BIO_ctrl_pending(read_buf) < minsize) return 0;
	return BIO_read(this->read_buf, data, size);
}

int LinkNode::sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag){
	ERROR("[link] send command not implemented!");
	return -1;
}

void LinkNode::run(){
	// sending data to the link simply means that we are sending data through
	// the chain of connections. So we can just use the next nodes send 
	// function to encode the data and get it out to it's destination. 
	int rc;
	char tmp[SOCKET_BUF_SIZE];
	
	Node::run();
	
	// if the link is now connected
	if((this->state & CON_STATE_INITIALIZED) && this->_output && this->_output->state & CON_STATE_CONNECTED){
		LOG("[link] link connected!");
		
		this->url = this->_output->url;
		
		this->state = CON_STATE_ESTABLISHED;
	}
	
	if(this->state & CON_STATE_CONNECTED){
		// send/recv data
		while(!BIO_eof(this->write_buf)){
			if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
				//LOG("LINK: sending "<<rc<<" bytes of data!");
				this->_output->send(tmp, rc);
			}
		}
		if((rc = this->_output->recv(tmp, sizeof(tmp)))>0){
			//LOG("LINK: received "<<rc<<" bytes of data!");
			BIO_write(this->read_buf, tmp, rc);
		}
	}
	
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(this->_output && this->_output->state & CON_STATE_DISCONNECTED){
		//LOG("LINK: underlying connection lost. Disconnected!");
		this->state = CON_STATE_DISCONNECTED;
	}
	if(this->_output && this->_output->state & CON_STATE_IDLE){
		//LOG("LINK: going idle..");
		this->state |= CON_STATE_IDLE;
	}
}
int LinkNode::listen(const URL &url){
	ERROR("[link] listen not implemented!");
	return -1;
}

void LinkNode::close(){
	this->state = CON_STATE_WAIT_CLOSE;
	
	if(!this->_output){
		this->state = CON_STATE_DISCONNECTED;
		return;
	}
	
	while(!BIO_eof(this->write_buf)){
		char tmp[SOCKET_BUF_SIZE];
		int rc;
		if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
			this->_output->send(tmp, rc);
		}
	}
	this->_output->close();
}

