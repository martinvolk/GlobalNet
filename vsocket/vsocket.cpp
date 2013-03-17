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

#include "vsocket.h"
#include "local.h"
#include <math.h>

#define SEND_SOCK(sock, msg) { stringstream ss; ss<<msg<<endl; VSL::send(sock, ss.str().c_str(), ss.str().length());}

string con_state_to_string(int state){
	switch(state){
		case CON_STATE_UNINITIALIZED:
			return "CON_STATE_UNINITIALIZED";
		case CON_STATE_INITIALIZED:
			return "CON_STATE_INITIALIZED";
		case CON_STATE_CONNECTING	:
			return "CON_STATE_CONNECTING";
		case CON_STATE_LISTENING:
			return "CON_STATE_LISTENING";
		case CON_STATE_SSL_HANDSHAKE:
			return "CON_STATE_SSL_HANDSHAKE";
		case CON_STATE_RELAY_PENDING:
			return "CON_STATE_RELAY_PENDING";
		case CON_STATE_ESTABLISHED:
			return "CON_STATE_ESTABLISHED";
		case CON_STATE_WAIT_CLOSE	:
			return "CON_STATE_WAIT_CLOSE";
		case CON_STATE_DISCONNECTED:
			return "CON_STATE_DISCONNECTED";
		default: 
			return "UNKNOWN";
	}
	return "";
}



namespace VSL{
	static shared_ptr<Network> net;
	static map<VSL::VSOCKET, shared_ptr<Node> > sockets;
	static pthread_t worker;
	static pthread_mutex_t mu;
	static bool running = false;
	
	
	static shared_ptr<Node> _find_socket(VSOCKET socket){
		map<VSOCKET, shared_ptr<Node> >::iterator it = sockets.find(socket);
		if(it != sockets.end()){
			return (*it).second;
		}
		return shared_ptr<Node>();
	}
	
	static VSOCKET _create_socket(){
		VSOCKET r;
		while(true){
			r = rand();
			if(sockets.find(r) == sockets.end()){
				sockets[r] = shared_ptr<Node>();
				return r;
			}
		}
		return -1;
	}
	
	static void *_vsl_worker(void *data){
		unsigned long usec = 0;
		while(true){
			if((usec % 100) == 0 && LOGLEVEL > 1){
				cout<<"V";
				fflush(stdout);
			}
			usec++;
			
			LOCK(mu, 0);
			if(!running) break;
			
			for(map<VSOCKET, shared_ptr<Node> >::iterator it = sockets.begin(); 
				it != sockets.end(); it++){
				if((*it).second)
					(*it).second->run();
			}
			net->run();
			UNLOCK(mu, 0);
			usleep(1000);
		}
		return 0;
	}
	
	int init(){
		net = shared_ptr<Network>(new Network());
		net->init();
		running = true;
		pthread_mutex_init(&mu, 0);
		pthread_create(&worker, 0, &_vsl_worker, 0);
		return 1;
	}
	
	void shutdown(){
		LOCK(mu, 0);
		for(map<VSOCKET, shared_ptr<Node> >::iterator it = sockets.begin(); 
				it != sockets.end(); it++){
			if(!(*it).second) continue;
			(*it).second->close();
			(*it).second.reset();
		}
		
		sockets.clear();
		
		running = false;
		UNLOCK(mu, 0);
		void *ret;
		pthread_join(worker, &ret);
		
		net.reset();
	}
	
	
	int get_peers_allowing_connection_to(const URL &url, 
					vector<PEERINFO> &peers, unsigned int maxcount){
		LOCK(mu,0);
		peers.reserve(peers.size()+maxcount);
		vector<PeerDatabase::Record> random = net->m_pPeerDb->random(maxcount);
		for(vector<PeerDatabase::Record>::iterator it = random.begin();
			it != random.end(); it++){
				PEERINFO pi;
				pi.url = (*it).peer;
				peers.push_back(pi);
		}
		return random.size(); 		
	}
	
	VSL::VSOCKET socket(){
		LOCK(mu,0);
		VSOCKET sock = _create_socket();
		sockets[sock] = shared_ptr<Node>();
		return sock;
	}
	
	int connect(VSL::VSOCKET socket, const list<URL> &peers){
		LOCK(mu,0);
		shared_ptr<Node> tun = _find_socket(socket);
		if(tun) tun.reset(); 
		tun = net->createTunnel(peers);
		sockets[socket] = tun;
		return 0;
	}
	
	int connect(VSOCKET socket, const URL &url){
		LOCK(mu,0);
		shared_ptr<Node> con = _find_socket(socket);
		if(con){
			con->close();
			con.reset();
		}
		con = net->connect(url);
		sockets[socket] = con;
		return 0;
	}
	
	int bind(VSOCKET socket, const URL &url){
		LOCK(mu,0);
		shared_ptr<Node> con = _find_socket(socket);
		if(!con)
			con = net->createNode(url.protocol());
		if(con){
			sockets[socket] = con;
			return con->bind(url);
		}
		return -1;
	}
	
	VSL::VSOCKET accept(VSL::VSOCKET socket){
		LOCK(mu,0);
		shared_ptr<Node> con = _find_socket(socket);
		if(con){
			unique_ptr<Node> client = con->accept();
			if(client){
				VSOCKET s = _create_socket();
				sockets[s] = move(client); 
				return s;
			}
			return 0; // listening but no connection
		}
		return -1; // invalid descriptor 
	}
	
	
	int listen(VSOCKET socket, const URL &url){
		LOCK(mu,0);
		shared_ptr<Node> con = _find_socket(socket);
		if(!con){
			con = net->createNode(url.protocol());
			sockets[socket] = con;
		}
		if(con){
			return con->listen(url); 
		}
		return -1;
	}
	
	int listen(VSOCKET socket, const list<URL> &url){
		LOCK(mu,0);
		shared_ptr<Node> tun = _find_socket(socket);
		if(tun) tun.reset(); 
		
		if(url.size() > 1){
			tun = net->createTunnel(list<URL>(url.begin(), std::prev(url.end())));
			URL u = *(std::prev(url.end()));
			LOG(3, "VSL: attempting to listen remotely on "<<u.url());
			tun->listen(u);
		}
		else {
			URL u = (*url.begin());
			tun = net->createNode(u.protocol());
			if(tun){
				LOG(3, "VSL: attempting to listen on "<<u.url());
				tun->listen(u);
			}
		}
		sockets[socket] = tun;
		return -1;
	}
	
	int send(VSOCKET socket, const char *data, size_t size){
		LOCK(mu,0);
		shared_ptr<Node> con = _find_socket(socket);
		if(con){
			return con->send(data, size);
		}
		return -1;
	}
	
	int recv(VSOCKET socket, char *data, size_t size){
		LOCK(mu,0);
		shared_ptr<Node> con = _find_socket(socket);
		if(con){
			return con->recv(data, size);
		}
		return -1;
	}
	
	int close(VSOCKET sock){
		LOCK(mu,0);
		map<VSOCKET, shared_ptr<Node> >::iterator it = sockets.find(sock);
		if(it != sockets.end()){
			if((*it).second){
				(*it).second->close();
				(*it).second.reset();
			}
			sockets.erase(it);
			return 1;
		}
		return -1;
	}
	
	int getsockinfo(VSOCKET sock, SOCKINFO *info){
		LOCK(mu,0);
		shared_ptr<Node> n = _find_socket(sock);
		if(!n) return -1;
		if(n->state & CON_STATE_CONNECTING)
			info->state = VSOCKET_CONNECTING;
		else if(n->state & CON_STATE_CONNECTED)
			info->state = VSOCKET_CONNECTED;
		else if(n->state & CON_STATE_DISCONNECTED)
			info->state = VSOCKET_DISCONNECTED;
		else if(n->state & CON_STATE_IDLE)
			info->state = VSOCKET_IDLE;
		else if(n->state & CON_STATE_LISTENING)
			info->state = VSOCKET_LISTENING;
			
		info->is_connected = (n->state & CON_STATE_CONNECTED) != 0;
		return 0;
	}
	bool getsockopt(VSOCKET sock, const string &option, string &dst){
		LOCK(mu,0);
		shared_ptr<Node> n = _find_socket(sock);
		if(n){
			return n->get_option(option, dst);
		}
		return false;
	}
	
	void print_stats(int socket){
		LOCK(mu,0);
		uint np = 0;
		for(map<string, shared_ptr<Node> >::iterator it = net->m_Peers.begin();
				it != net->m_Peers.end(); it++ ){
			VSLNode* peer = dynamic_cast<VSLNode*>((*it).second.get());
			SEND_SOCK(socket, "peer: " << peer->url.url()<<" state: "<<con_state_to_string(peer->state));
			np++;
		}
		SEND_SOCK(socket, "Total: "<<np<<" peers.");
	}
	
	string to_string(int value){
		stringstream ss;
		ss<<value;
		return ss.str();
	}
}
