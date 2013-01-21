#include "local.h"

Network::Peer::~Peer(){
	if(this->socket) delete socket;
}

void Network::Peer::run(){
	if(socket) socket->run();
}

/*
void Network::Peer::addListener(PeerListener *l){
	if(listener) delete listener;
	listener = l;
}
*/
bool Network::Peer::is_connected(){
	if(socket && socket->state & CON_STATE_CONNECTED){
		return true;
	}
	return false;
}

bool Network::Peer::is_disconnected(){
	return socket && socket->state & CON_STATE_DISCONNECTED;
}
