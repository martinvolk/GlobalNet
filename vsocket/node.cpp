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

Node::Node(weak_ptr<Network> net){
	m_pNetwork = net;
	this->type = NODE_NONE;
	
	/* set up the memory-buffer BIOs */
	/*this->read_buf = BIO_new(BIO_s_mem());
	this->write_buf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(this->read_buf, -1);
	BIO_set_mem_eof_return(this->write_buf, -1);
	
	this->in_read = BIO_new(BIO_s_mem());
	this->in_write = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(this->in_read, -1);
	BIO_set_mem_eof_return(this->in_write, -1);
	*/
	this->state = CON_STATE_INITIALIZED;
}

Node::~Node(){
	LOG(3,"NODE: deleting "<<this<<": "<<url.url());
	this->close();
	
	this->state = CON_STATE_UNINITIALIZED;
	LOG(3,"NODE: ======== "<<this<<": "<<url.url());
}

void Node::close(){
	/*if(read_buf) BIO_free(this->read_buf);
	if(write_buf) BIO_free(this->write_buf);
	if(in_read) BIO_free(this->in_read);
	if(in_write) BIO_free(this->in_write);
	
	read_buf = write_buf = in_read = in_write = 0;
	*/
	//m_pTransportLayer.reset();
}

/** internal function for establishing internal connections to other peers
Establishes a UDT connection using listen_port as local end **/
unique_ptr<Node> Node::accept(){
	ERROR("CON_accept not implemented!");
	return unique_ptr<Node>();
}

int Node::connect(const URL &url){
	ERROR("CON_connect not implemented!");
	return -1;
}

/*
int Node::sendCommand(NodeMessage msg, const char *data, size_t size, const string &tag){
	// the default behavior is to simply pass the command down the line
	if(this->m_pTransportLayer)
		this->m_pTransportLayer->sendCommand(msg, data, size, tag);
	return 1;
}

int Node::sendCommand(const Packet &pack){
	// the default behavior is to simply pass the command down the line
	if(this->m_pTransportLayer)
		this->m_pTransportLayer->sendCommand(pack);
	//this->sendCommand((NodeMessage)pack.cmd.code, pack.data, pack.cmd.size, pack.cmd.hash.hex());
	return 1;
}
*/
/*
int Node::recvCommand(Packet *dst){
	// only used by Peer. 
	//ERROR("CON: call to recvCommand(): NOT IMPLEMENTED!"); 
	return 0;
}
*/
void Node::run(){
	//m_pTransportLayer->run();
}
int Node::listen(const URL &url){
	ERROR("CON_listen not implemented!");
	return -1;
}
void Node::peg(Node *other){
	ERROR("CON_bridge not implemented!");
}
/*
void Node::output(shared_ptr<Node> other){
	m_pTransportLayer.reset();
	this->m_pTransportLayer = other;
	if(other)
		other->input(shared_ptr<Node>(this));
}
void Node::input(shared_ptr<Node> other){ 
	//this->m_pInput = other;
	//other->setOutput(this);
}
shared_ptr<Node> Node::output(){
	return this->m_pTransportLayer.lock();
}
shared_ptr<Node> Node::input(){
	//return this->m_pInput;
	return shared_ptr<Node>();
}
*/
void Node::set_option(const string &opt, const string &val){
	options[opt] = val;
}

bool Node::get_option(const string &opt, string &res){
	if(options.find(opt) != options.end()){
		res = options[opt];
		return true;
	}
	return false;
}

