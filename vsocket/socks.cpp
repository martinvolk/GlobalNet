#include "local.h"

typedef enum{
	SOCKS_STATE_INIT = 1<<16,
	SOCKS_STATE_1 = 1<<0,
	SOCKS_STATE_2 = 1<<1,
	SOCKS_STATE_3 = 1<<2,
	SOCKS_STATE_4 = 1<<3,
	SOCKS_STATE_5 = 1<<4,
	SOCKS_STATE_6 = 1<<5,
	SOCKS_STATE_7 = 1<<6,
	SOCKS_STATE_8 = 1<<7, 
	SOCKS_STATE_9 = 1<<9,
	SOCKS_STATE_10 = 1<<10
}SocksState; 

#define SOCKS_TIMEOUT 10

SocksNode::SocksNode():
	listen_socket(new TCPNode()){
	
}

SocksNode::~SocksNode(){
	delete listen_socket;
}

int SocksNode::send(const char *data, size_t size, size_t minsize){
	// sends data to the 
	return -1;
}
int SocksNode::recv(char *data, size_t size, size_t minsize){
	return -1;
}
int SocksNode::listen(const char *host, uint16_t port){
	return listen_socket->listen(host, port);
}
Node* SocksNode::accept(){
	if(accepted.size()) {
		Node *ret = (*accepted.begin()).second;
		accepted.pop_front();
		return ret;
	}
	return 0;
}
void SocksNode::run(){
	Node *client = 0; 
	if((client = listen_socket->accept()) != 0){
		// push the client into the queue of socks nodes
		LOG("SocksNode: accepted connection from "<<client->host<<":"<<client->port);
		socks_state_t state; 
		state.last_event = time(0);
		state.state = SOCKS_STATE_INIT;
		accept_queue.push_back(pair<socks_state_t, Node*>(state, client));
	}
	
	// go through the accept queue and try to handle all requests
	for(list< pair<socks_state_t, Node*> >::iterator it = accept_queue.begin(); 
		it != accept_queue.end(); ){
		socks_state_t &state = (*it).first;
		Node *c = (*it).second;
		c->run();
		
		if(time(0) - state.last_event > SOCKS_TIMEOUT){
			LOG("SOCKS: connection timed out!");
			c->close();
			delete c;
			accept_queue.erase(it++);
			continue;
		}
		if(state.state & SOCKS_STATE_INIT){
			// try to receive handshake. 
			// skip first packet (2 bytes)
			if(c->recv((char*)&state.socks, 2, 2) == 2){
				if(int(state.socks.version) != 5){
					LOG("SOCKS: client specified unsupported socks version: "<<(int)state.socks.version);
					c->close();
					delete c;
					accept_queue.erase(it++);
					continue;
				}
				state.state = SOCKS_STATE_1;
			}
		}
		if(state.state & SOCKS_STATE_1){
			// recv the methods and discard them
			if(c->recv((char*)&state.socks.data, state.socks.code, state.socks.code) == state.socks.code){
				state.state = SOCKS_STATE_2;
			}
		}
		if(state.state & SOCKS_STATE_2){
			// send version and send method 0 (no authentication) 
			state.socks.version = 5;
			state.socks.code = 0;
			c->send((const char*)&state.socks, 2);
			state.state = SOCKS_STATE_3;
		}
		if(state.state & SOCKS_STATE_3){
			// receive the command request
			if(c->recv((char*)&state.socks, 4, 4)== 4){
				state.state = SOCKS_STATE_4;
			}
		}
		if(state.socks.atype == 1 && state.state & SOCKS_STATE_4){
			
			struct {uint32_t ip; uint16_t port;} tmp;
			if(c->recv((char*)&tmp, 6, 6) == 6){
				in_addr addr;
				addr.s_addr = tmp.ip;
				c->set_option("socks_request_host", inet_ntoa(addr));
				c->set_option("socks_request_port", VSL::to_string(ntohs(tmp.port)));
				state.state = SOCKS_STATE_8;
			}
		}
		if(state.socks.atype == 3 && state.state & SOCKS_STATE_4) // domain name
		{
			// recv size
			if(c->recv((char*)&state.socks.data, 1, 1) == 1)
				state.state = SOCKS_STATE_5;
		}
		if(state.socks.atype == 3 && state.state & SOCKS_STATE_5){
			char host[256];
			int size = state.socks.data[0];
			if(c->recv((char*)host, size, size) == size){
				host[size] = 0;
				c->set_option("socks_request_host", host);
				state.state = SOCKS_STATE_6;
			}
		}
		if(state.socks.atype == 3 && state.state & SOCKS_STATE_6){
			if(c->recv((char*)&port, 2, 2)==2){
				c->set_option("socks_request_port", VSL::to_string(ntohs(port)));
				state.state = SOCKS_STATE_8;
			}
		}
		if(state.socks.atype == 4){
				ERROR("SOCKS: IPv6 not supported!");
				c->close();
				accept_queue.erase(it++);
				continue;
		}
		if(state.state & SOCKS_STATE_8){
			string host, port;
			c->get_option("socks_request_host", host);
			c->get_option("socks_request_port", port);
			LOG("SOCKS v"<<int(state.socks.version)<<", CODE: "<<int(state.socks.code)<<", AT:" <<
					int(state.socks.atype)<<", IP: "<<host<<":"<<port);
			state.state = SOCKS_STATE_9;
		}
		if(state.state & SOCKS_STATE_9){
			// the connection has successfully been accepted. 
			// send success message to the client and put the node into accept queue.
			/// send success packet to the connected client
			state.socks.code = 0;
			state.socks.atype = 1;
			in_addr a;
			inet_aton("127.0.0.1", &a);
			memset(state.socks.data, 0, 6);
			c->send((const char*)&state.socks, 10);
			
			accepted.push_back(pair<time_t, Node*>(time(0), c));
			accept_queue.erase(it++);
			continue;
		}
		it++;
	}
	
	// go through the accepted connections queue and clear out connections that have timed out. 
	for(list< pair<time_t, Node*> >::iterator it = accepted.begin(); 
			it != accepted.end(); ){
		(*it).second->run();
		if((*it).second->state & CON_STATE_INVALID || time(0) - (*it).first > SOCKS_TIMEOUT){
			accepted.erase(it++);
			continue;
		}
		it++;
	}
}

void SocksNode::close(){
	
}
