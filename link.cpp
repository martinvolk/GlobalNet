#include "gclient.h"

/// starts a listening service for the local end of the link on the given port
/// all input on that port will be sent as data to the last hop.
int LNK_listenLocal(const string &host, int port){
	return 0;
}

/// send data over the link to the last host in the link
int LNK_send(Link &self, const char *data, size_t size){
	// send it from the "back" of the link. A link is like a telescopic tunnel. Front is the end node. 
	if(!self.length)
		return 0;
	Connection *back = self.nodes[self.length-1];
	return back->send(*back, data, size);
}
int LNK_recv(Link &self, char *data, size_t size){
	if(!self.length)
		return 0;
	// send it from the "back" of the link. A link is like a telescopic tunnel. Front is the end node. 
	Connection *back = self.nodes[self.length-1];
	return back->recv(*back, data, size);
}

/// starts a new connection on the remote end of the link 
/// arguments are host to connect to and port
int LNK_connect(Link &self, const string &host, int port, RelayProtocol proto){
	// create a new conneciton and bridge it with the previous connection
	Connection *node = NET_allocConnection(*self.net);
	if(!node) return -1;
	
	if(proto == REL_PROTO_INTERNAL_CLIENT)
		CON_initPeer(*node, true);
	else if(proto == REL_PROTO_TCP)
		CON_initTCP(*node, true);
		
	if(self.length)
		node->bridge(*node, (self.nodes[self.length-1]));
	
	if(node->connect(*node, host.c_str(), port)){
		if(self.length == ARRSIZE(self.nodes)){
			ERROR("Link length is too long! MAX: "+ARRSIZE(self.nodes));
			return 0;
		}
		self.nodes[self.length] = node;
		self.length++;
	} else {
		NET_free(node);
	}
	/*
	// issue a relay connect to the end of the link. 
	// This will connect to the outside world allowing us to send CMD_DATA packets
	// to the outside server. 
	
	Packet pack;
	
	stringstream ss;
	ss<<"tcp:"<<host<<":"<<port;
	string str = ss.str();
	pack.cmd.code = RELAY_CONNECT;
	pack.data = vector<char>(str.begin(), str.end());
	LNK_send(self, pack);*/
	return 1;
}

/**
Writing data to a link stores it in the links write_buf
**/ 
int LNK_sendData(Link &self, const char *data, size_t size) {
	Packet pack; 
	
	if(!self.length){
		cout<<"[error] can not send data to link because link has no nodes!"<<endl;
		return -1;
	}
	LOG("[link_send_data] sending DATA of "<<size);
	size = min(ARRSIZE(pack.data), size);
	pack.cmd.code = CMD_DATA;
	pack.cmd.size = size;
	memcpy(pack.data, data, size);
	Connection *back = self.nodes[self.length-1];
	return back->send(*back, pack.c_ptr(), pack.size());
}

/** 
Reading data reads it from the links read_buf. Read buf is filled upon a flush
**/ 
int LNK_recvData(Link &self, vector<char> *data){
	Packet pack;
	//while(CON_recvPacket((&self.nodes.begin()), pack)){
	//	cout << "LINK: received packet!"<<endl;
	//}
	return 0;
}

void LNK_run(Link &self){
	
}

void LNK_shutdown(Link &self){
	for(uint c = 0;c<self.length; c++){
		CON_close(*self.nodes[c]);
	}
	self.length = 0; 
}
