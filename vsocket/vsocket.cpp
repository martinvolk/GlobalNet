/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
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
	static Network *net;
	static map<VSL::VSOCKET, Node*> sockets;
	
	int init(){
		net = new Network();
		return 1;
	}
	
	static Node* _find_socket(VSOCKET socket){
		map<VSOCKET, Node*>::iterator it = sockets.find(socket);
		if(it != sockets.end()){
			return (*it).second;
		}
		return 0;
	}
	
	static VSOCKET _create_socket(){
		VSOCKET r;
		while(true){
			r = rand();
			if(sockets.find(r) == sockets.end()){
				sockets[r] = 0;
				return r;
			}
		}
		return -1;
	}
	
	static bool _parse_host_port(const string &host_port, string *host, int *port){
		vector<string> peer;
		tokenize(host_port, string(":"), peer);
		if(peer.size() > 1){
			*port = atoi(peer[1].c_str());
			*host = peer[0];
			return true;
		}
		return false;
	}
	
	VSL::VSOCKET socket(VSL::SOCKPROTO type){
		const char *type_str;
		if(type == VSL::SOCKET_TCP) type_str = "tcp";
		else if(type == VSL::SOCKET_SOCKS) type_str = "socks";
		else ERROR("TYPE NOT IMPLEMENTED!");
		
		Node *con = Node::createNode(type_str);
		VSOCKET sock = _create_socket();
		sockets[sock] = con;
		return sock;
	}
	
	VSL::VSOCKET tunnel(const char *path){
		vector<string> hosts;
		tokenize(path, string(">"), hosts);
		if(!hosts.size()){
			ERROR("tunnel: ERROR PARSING PATH STRING!");
			return -1;
		}
		string dest = hosts[hosts.size()-1];
		string host; int port;
		_parse_host_port(dest.c_str(), &host, &port);
		stringstream tmp; 
		
		tmp<<"*";
		for(unsigned int c=0;c<hosts.size()-1;c++) 
			tmp<<">"<<hosts[c];
		
		INFO("VSOCKET: setting up tunnel: "<<tmp.str()<<">"<<host<<":"<<port);
		
		Node *tun = net->createLink(tmp.str().c_str());
		if(tun){
			stringstream ss;
			ss<<"tcp:"<<host<<":"<<port;
			tun->connect(ss.str().c_str(), 0);
			
			VSOCKET sock = _create_socket();
			sockets[sock] = tun;
			return sock;
		}
		
		return -1;
	}
	
	VSL::VSOCKET accept(VSL::VSOCKET socket){
		Node *con = _find_socket(socket);
		if(con){
			Node *client = con->accept();
			if(client){
				VSOCKET s = _create_socket();
				sockets[s] = client; 
				return s;
			}
			return 0; // listening but no connection
		}
		return -1; // invalid descriptor 
	}
	
	int add_peer(const char *host_port){
		string host;
		int port;
		if(_parse_host_port(host_port, &host, &port)){
			net->connect(host.c_str(), port);
			//Peer *node = net->createPeer();
			//node->socket->connect(host.c_str(), port);
			return 1;
		}
		return -1;
	}
	
	int connect(VSOCKET socket, const char *host, uint16_t port ){
		Node *con = _find_socket(socket);
		
		if(con){
			con->connect(host, port);
			return 1;
		}
		return -1;
	}
	
	int listen(VSOCKET socket, const char *host_port){
		Node *con = _find_socket(socket);
		
		if(con){
			string host;
			int port;
			if(_parse_host_port(host_port, &host, &port))
				return con->listen(host.c_str(), port); 
		}
		return -1;
	}
	
	int send(VSOCKET socket, const char *data, size_t size){
		Node *con = _find_socket(socket);
		if(con){
			return con->send(data, size);
		}
		return -1;
	}
	
	int recv(VSOCKET socket, char *data, size_t size){
		Node *con = _find_socket(socket);
		if(con){
			return con->recv(data, size);
		}
		return -1;
	}
	
	void run(){
		for(map<VSOCKET, Node*>::iterator it = sockets.begin(); 
				it != sockets.end(); it++)
			(*it).second->run();
			
		net->run();
	}
	
	int close(VSOCKET sock){
		map<VSOCKET, Node*>::iterator it = sockets.find(sock);
		if(it != sockets.end()){
			(*it).second->close();
			delete (*it).second;
			sockets.erase(it);
			return 1;
		}
		return -1;
	}
	
	int getsockinfo(VSOCKET sock, SOCKINFO *info){
		Node *n = _find_socket(sock);
		if(!n) return -1;
		if(n->state & CON_STATE_CONNECTED)
			info->state = VSOCKET_CONNECTED;
		else if(n->state & CON_STATE_DISCONNECTED)
			info->state = VSOCKET_DISCONNECTED;
		else if(n->state & CON_STATE_IDLE)
			info->state = VSOCKET_IDLE;
			
		info->is_connected = (n->state & CON_STATE_CONNECTED) != 0;
		return 0;
	}
	bool getsockopt(VSOCKET sock, const string &option, string &dst){
		Node *n = _find_socket(sock);
		if(n){
			return n->get_option(option, dst);
		}
		return false;
	}
	void shutdown(){
		delete net;
	}
	
	void print_stats(int socket){
		uint np = 0;
		for(list<Network::Peer*>::iterator it = net->peers.begin();
				it != net->peers.end(); it++ ){
			Network::Peer *peer = (*it);
			SEND_SOCK(socket, "peer: " << peer->address.ip << ":"<<peer->address.port<<" is_connected: "<<peer->is_connected());
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
