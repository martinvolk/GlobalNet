#include "local.h"

static void *_peer_worker(void *data){
	Network::Peer *self = (Network::Peer*)data;
	self->loop();
	return 0;
}

Network::Peer::Peer(VSLNode *socket){
	this->socket = socket;
	running = true;
	pthread_create(&worker, 0, &_peer_worker, this);
}

Network::Peer::~Peer(){
	if(this->socket) delete socket;
	running = false;
	void *ret;
	pthread_join(this->worker, &ret);
}

void Network::Peer::loop(){
	while(running) {
		LOCK(mu, 0);
		address.ip = socket->host;
		address.port = socket->port;
		socket->run();
		usleep(100);
	}
}

int Network::Peer::recvCommand(Packet *dst){
	LOCK(mu, 0);
	return socket->recvCommand(dst);
}

int Network::Peer::sendCommand(NodeMessage msg, const char *data, size_t size){
	LOCK(mu, 0);
	return socket->sendCommand(msg, data, size);
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
