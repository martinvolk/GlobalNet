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

SocksNode::SocksNode(shared_ptr<Network> net):
	Node(net),
	listen_socket(new TCPNode(net)){
	
}

SocksNode::~SocksNode(){
	
}

int SocksNode::send(const char *data, size_t size){
	// sends data to the 
	return -1;
}
int SocksNode::recv(char *data, size_t size, size_t minsize) const{
	return -1;
}
int SocksNode::listen(const URL &url){
	return listen_socket->listen(url);
}
unique_ptr<Node> SocksNode::accept(){
	if(accepted.size()) {
		unique_ptr<Node> ret = move((*accepted.begin()).second);
		accepted.pop_front();
		return move(ret);
	}
	return unique_ptr<Node>();
}
void SocksNode::run(){
	unique_ptr<Node> client; 
	if((client = listen_socket->accept())){
		// push the client into the queue of socks nodes
		LOG(1,"SocksNode: accepted connection from "<<client->url.url());
		socks_state_t state; 
		state.last_event = time(0);
		state.state = SOCKS_STATE_INIT;
		accept_queue.push_back(pair<socks_state_t, unique_ptr<Node> >(state, move(client)));
	}
	
	// go through the accept queue and try to handle all requests
	for(list< pair<socks_state_t, unique_ptr<Node> > >::iterator it = accept_queue.begin(); 
		it != accept_queue.end(); ){
		socks_state_t &state = (*it).first;
		(*it).second->run();
		
		if(time(0) - state.last_event > SOCKS_TIMEOUT){
			LOG(1,"SOCKS: connection timed out!");
			(*it).second->close();
			accept_queue.erase(it++);
			continue;
		}
		if(state.state & SOCKS_STATE_INIT){
			// try to receive handshake. 
			// skip first packet (2 bytes)
			if((*it).second->recv((char*)&state.socks, 2, 2) == 2){
				if(int(state.socks.version) != 5){
					LOG(1,"SOCKS: client specified unsupported socks version: "<<(int)state.socks.version);
					(*it).second->close();
					accept_queue.erase(it++);
					continue;
				}
				LOG(3,"SOCKS: accepted version.");
				state.state = SOCKS_STATE_1;
			}
		}
		if(state.state & SOCKS_STATE_1){
			// recv the methods and discard them
			if((*it).second->recv((char*)&state.socks.data, state.socks.code, state.socks.code) == state.socks.code){
				state.state = SOCKS_STATE_2;
				LOG(3,"SOCKS: accepted methods.");
			}
		}
		if(state.state & SOCKS_STATE_2){
			// send version and send method 0 (no authentication) 
			state.socks.version = 5;
			state.socks.code = 0;
			(*it).second->send((const char*)&state.socks, 2);
			state.state = SOCKS_STATE_3;
			LOG(3,"SOCKS: sent chosen method.");
		}
		if(state.state & SOCKS_STATE_3){
			// receive the command request
			if((*it).second->recv((char*)&state.socks, 4, 4)== 4){
				state.state = SOCKS_STATE_4;
				LOG(3,"SOCKS: accepted command request.");
			}
		}
		if(state.socks.atype == 1 && state.state & SOCKS_STATE_4){
			struct {uint32_t ip; uint16_t port;} tmp;
			if((*it).second->recv((char*)&tmp, 6, 6) == 6){
				in_addr addr;
				addr.s_addr = tmp.ip;
				(*it).second->set_option("socks_request_host", inet_ntoa(addr));
				(*it).second->set_option("socks_request_port", VSL::to_string(ntohs(tmp.port)));
				state.state = SOCKS_STATE_8;
				LOG(3,"SOCKS: got ip address.");
			}
		}
		if(state.socks.atype == 3 && state.state & SOCKS_STATE_4) // domain name
		{
			// recv size
			if((*it).second->recv((char*)&state.socks.data, 1, 1) == 1)
				state.state = SOCKS_STATE_5;
		}
		if(state.socks.atype == 3 && state.state & SOCKS_STATE_5){
			char host[256];
			int size = state.socks.data[0];
			if((*it).second->recv((char*)host, size, size) == size){
				host[size] = 0;
				(*it).second->set_option("socks_request_host", host);
				state.state = SOCKS_STATE_6;
				LOG(3,"SOCKS: got domain name.");
			}
		}
		if(state.socks.atype == 3 && state.state & SOCKS_STATE_6){
			uint16_t port;
			if((*it).second->recv((char*)&port, 2, 2)==2){
				(*it).second->set_option("socks_request_port", VSL::to_string(ntohs(port)));
				state.state = SOCKS_STATE_8;
				LOG(3,"SOCKS: got port.");
			}
		}
		if(state.socks.atype == 4){
				ERROR("SOCKS: IPv6 not supported!");
				(*it).second->close();
				accept_queue.erase(it++);
				continue;
		}
		if(state.state & SOCKS_STATE_8){
			string host, port;
			(*it).second->get_option("socks_request_host", host);
			(*it).second->get_option("socks_request_port", port);
			LOG(1,"SOCKS v"<<int(state.socks.version)<<", CODE: "<<int(state.socks.code)<<", AT:" <<
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
			(*it).second->send((const char*)&state.socks, 10);
			
			accepted.push_back(pair<time_t, unique_ptr<Node> >(time(0), move((*it).second)));
			accept_queue.erase(it++);
			continue;
		}
		it++;
	}
	
	// go through the accepted connections queue and clear out connections that have timed out. 
	for(list< pair<time_t, unique_ptr<Node> > >::iterator it = accepted.begin(); 
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
