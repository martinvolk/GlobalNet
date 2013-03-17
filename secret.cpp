#include "gclient.h"

SecretService::SecretService(){
	
}

SecretService::~SecretService(){
	LOG(3, "SECRET: deleting..");
	for(list<pair<VSL::VSOCKET, URL> >::iterator it = m_ListeningChains.begin();
		it != m_ListeningChains.end(); it++){
		VSL::close((*it).first);
	}
	for(list<pair<VSL::VSOCKET, VSL::VSOCKET> >::iterator it = m_ActiveChains.begin();
			it != m_ActiveChains.end(); it++){
		VSL::close((*it).first);
		VSL::close((*it).second);
	}
}

void addConnectionChain(const URL &localaddr, const list<URL> &urls, const URL &remoteaddr){
	
}
	
void SecretService::addListeningChain(const URL &serviceaddr, const list<URL> &urls, const URL &listenaddr){
	VSL::VSOCKET tunnel = VSL::socket();
	list<URL> path = list<URL>(urls.begin(), urls.end());
	path.push_back(listenaddr);
	VSL::listen(tunnel, path);
	m_ListeningChains.push_back(pair<VSL::VSOCKET, URL>(tunnel, serviceaddr));
}

void SecretService::run(){
	for(list<pair<VSL::VSOCKET, URL> >::iterator it = m_ListeningChains.begin();
		it != m_ListeningChains.end(); it++){
		VSL::VSOCKET client = VSL::accept((*it).first);
		if(client){
			LOG(3, "SECRET: client connected!");
			VSL::VSOCKET service = VSL::socket();
			VSL::connect(service, (*it).second);
			m_ActiveChains.push_back(pair<VSL::VSOCKET, VSL::VSOCKET>(client, service));
		}
	}
	
	// forward data between the active chains
	for(list<pair<VSL::VSOCKET, VSL::VSOCKET> >::iterator it = m_ActiveChains.begin();
			it != m_ActiveChains.end(); it++){
		char tmp[SOCKET_BUF_SIZE];
		int rc;
		VSL::SOCKINFO info_service, info_client;
		VSL::getsockinfo((*it).first, &info_client);
		VSL::getsockinfo((*it).second, &info_service);
		
		if(info_service.state == VSL::VSOCKET_DISCONNECTED ||
				info_client.state == VSL::VSOCKET_DISCONNECTED){
			LOG(3, "SECRET: deleting active chain!");
			it = m_ActiveChains.erase(it);
			continue;
		}
		
		if(info_service.state == VSL::VSOCKET_CONNECTED ||
				info_client.state == VSL::VSOCKET_CONNECTED){
			if((rc = VSL::recv((*it).first, tmp, SOCKET_BUF_SIZE))>0){
				LOG(3, "SECRET: passing data to service..");
				VSL::send((*it).second, tmp, rc);
			}
			if((rc = VSL::recv((*it).second, tmp, SOCKET_BUF_SIZE))>0){
				LOG(3, "SECRET: passing data from service..");
				VSL::send((*it).first, tmp, rc);
			}
		}
	}
}
