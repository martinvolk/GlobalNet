/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
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

int LinkNode::connect(const char *hostname, uint16_t port){
	// calling connect on a link can have several meanings. If the host starts
	// with "peer:" the link will connect to a peer. If the link is already 
	// connected to something then it will issue sendCommand and try to 
	// connect from the already connected host to the next one. 
	
	// parse the address
	string str = string(hostname);
	vector<string> tokens;
	tokenize(str, ":",tokens);
	string proto = "";
	string host = "";
	if(tokens.size() == 3){
		proto = tokens[0];
		host = tokens[1];
		port = atoi(tokens[2].c_str());
	} else {
		ERROR("LINK URL FORMAT NOT SUPPORTED! PLEASE USE proto:host:port! "<<hostname);
	}
	
	if(proto.compare("tcp")==0){
		LOG("LINK: issuing remote connect command: connecting to "<<hostname);
		this->_output->sendCommand(RELAY_CONNECT, hostname, strlen(hostname));
	}
	else if(proto.compare("peer")==0){
		LOG("LINK: connecting to new node: "<<host<<":"<<port);
		// peg a peer on top of the current connection and issue a connect
		VSLNode *peer = new VSLNode(0);
		
		if(this->_output)
			peer->peg(this->_output);
		peer->connect(host.c_str(), port);
		this->_output = peer;
	}
	
	return 1;
}

int LinkNode::send(const char *data, size_t size){
	// we place the data in the link buffer and send it out later in the 
	// main loop. 
	LOG("LINK: send(): "<<size<<" bytes!");
	if(this->state & CON_STATE_INVALID) return -1;
	return BIO_write(this->write_buf, data, size);
}

int LinkNode::recv(char *data, size_t size){
	if(this->state & CON_STATE_INVALID) return -1;
	if(BIO_eof(this->read_buf)) return 0;
	return BIO_read(this->read_buf, data, size);
}

int LinkNode::sendCommand(NodeMessage cmd, const char *data, size_t size){
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
		
		this->host = this->_output->host;
		this->port = this->_output->port;
		
		this->state = CON_STATE_ESTABLISHED;
	}
	
	if(this->state & CON_STATE_CONNECTED){
		// send/recv data
		while(!BIO_eof(this->write_buf)){
			if((rc = BIO_read(this->write_buf, tmp, SOCKET_BUF_SIZE))>0){
				LOG("LINK: sending "<<rc<<" bytes of data!");
				this->_output->send(tmp, rc);
			}
		}
		if((rc = this->_output->recv(tmp, sizeof(tmp)))>0){
			LOG("LINK: received "<<rc<<" bytes of data!");
			BIO_write(this->read_buf, tmp, rc);
		}
	}
	
	// we always should check whether the output has closed so that we can graciously 
	// switch state to closed of our connection as well. The other connections 
	// that are pegged on top of this one will do the same. 
	if(this->_output && this->_output->state & CON_STATE_DISCONNECTED){
		LOG("LINK: underlying connection lost. Disconnected!");
		this->state = CON_STATE_DISCONNECTED;
	}
}
int LinkNode::listen(const char *host, uint16_t port){
	ERROR("[link] listen not implemented!");
	return -1;
}
void LinkNode::peg(Node *other){
	ERROR("[link] peg not implemented. It is not recommended to peg links.");
}

void LinkNode::close(){
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
	this->state = CON_STATE_WAIT_CLOSE;
}

LinkNode::LinkNode(){ 
	this->type = NODE_LINK;
	this->state = CON_STATE_INITIALIZED;
}

LinkNode::~LinkNode(){
	
}
