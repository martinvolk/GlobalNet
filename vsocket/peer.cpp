#include "local.h"

static void *_peer_worker(void *data){
	Network::Peer *self = (Network::Peer*)data;
	self->loop();
	return 0;
}

Network::Peer::Peer(VSLNode *socket){
	this->socket = socket;
	running = true;
	mu = new pthread_mutex_t();
	worker = new pthread_t();
	pthread_mutex_init(mu, 0);
	pthread_create(worker, 0, &_peer_worker, this);
}

Network::Peer::~Peer(){
	LOCK(*mu, 0);
	if(this->socket) delete socket;
	running = false;
	UNLOCK(*mu, 0);
	void *ret;
	pthread_join(*this->worker, &ret);
}

void Network::Peer::run(){
	LOCK(*mu, 0);
	address.ip = socket->host;
	address.port = socket->port;
	socket->run();
	UNLOCK(*mu, 0);
}
void Network::Peer::loop(){
	while(true) {
		LOCK(*mu, 0);
		if(running){
			address.ip = socket->host;
			address.port = socket->port;
			socket->run();
		}
		else break;
		UNLOCK(*mu, 0);
		usleep(100);
	}
}

int Network::Peer::recvCommand(Packet *dst){
	LOCK(*mu, 0);
	return socket->recvCommand(dst);
}

int Network::Peer::sendCommand(NodeMessage msg, const char *data, size_t size){
	LOCK(*mu, 0);
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
