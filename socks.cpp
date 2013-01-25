/*********************************************
GClient - GlobalNet P2P client
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "gclient.h"

///*******************************************
///********** SERVICE ************************
///*******************************************
/**
This model is used for both local and remote representation of the service
In local model we can have a socket where we accept connections and forward 
data to the remote end. On the remote end we can have a socket that connects 
to another host and relays information from that connection. **/

static const char *get_socket_ip(int socket){
	socklen_t len;
	struct sockaddr_storage addr;
	char ipstr[INET6_ADDRSTRLEN];

	len = sizeof addr;
	getpeername(socket, (struct sockaddr*)&addr, &len);

	// deal with both IPv4 and IPv6:
	if (addr.ss_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *)&addr;
			int port = ntohs(s->sin_port);
			inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
			return inet_ntoa(s->sin_addr);
	} else { // AF_INET6
			struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
			int port = ntohs(s->sin6_port);
			inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
			return "";
	}
	return "";
}

SocksService::SocksService(){
	local_socket = VSL::socket(VSL::SOCKET_SOCKS);
}
SocksService::~SocksService(){
	vector< pair<VSL::VSOCKET, VSL::VSOCKET> >::iterator it = this->local_clients.begin();
	while(it != this->local_clients.end()){
		VSL::close((*it).second);
		VSL::close((*it).first);
		it++;
	}
	VSL::close(local_socket);
}

void SocksService::put_socket_to_cache(const char *ip, VSL::VSOCKET socket){
	Cache::iterator it = cache.find(string(ip));
	if(it == cache.end()){
		map<VSL::VSOCKET, CachePost> m; 
		m[socket] = CachePost(socket, time(0));
		cache[string(ip)] = m;
		LOG("SOCKS: cache: putting into cache was successfull!");
		return;
	}
	//map<VSL::VSOCKET, CachePost>::iterator p = (*it).second.find(socket);
	//if(p != (*it).second.end()) return;
	LOG("SOCKS: cache: putting into cache was successfull! ("<<(*it).second.size()<<")");
	(*it).second[socket] = CachePost(socket, time(0));
}

VSL::VSOCKET SocksService::get_socket_from_cache(const char *ip){
	Cache::iterator it = cache.find(string(ip));
	if(it == cache.end()) return 0;
	
	// this function simultaneously clears invalid or disconnected sockets from the cache
	while((*it).second.size()){
		map<VSL::VSOCKET, CachePost>::iterator p = (*it).second.begin();
		VSL::VSOCKET ret = (*p).first;
		(*it).second.erase(p);
		VSL::SOCKINFO info;
		VSL::getsockinfo(ret, &info );
		if(info.is_connected){
			return ret;
		}
		else{
			VSL::close(ret);
		}
	}
	return 0;
}

void SocksService::run(){
	VSL::VSOCKET client; 
	if((client = VSL::accept(this->local_socket))>0){
		VSL::VSOCKET link = 0; //get_socket_from_cache(inet_ntoa(adr_clnt.sin_addr)); 
		string host, port;
		VSL::getsockopt(client, "socks_request_host", host);
		VSL::getsockopt(client, "socks_request_port", port);
		if(!link)
			link = VSL::tunnel(URL("tcp", host, atoi(port.c_str()))); 
		else {
			LOG("SOCKS: using previously opened socket from cache!");
			VSL::connect(link, URL("tcp", host, atoi(port.c_str())));
		}
		if(link > 0){
			this->local_clients.push_back(pair<VSL::VSOCKET, VSL::VSOCKET>(client, link));
		}
		else {
			VSL::close(client);
		}
	}
	/// process data from local clients
	vector< pair<VSL::VSOCKET, VSL::VSOCKET> >::iterator it = this->local_clients.begin();
	char buf[SOCKET_BUF_SIZE];
	while(it != this->local_clients.end()){
		VSL::VSOCKET sock = (*it).first;
		VSL::VSOCKET link = (*it).second;
		VSL::SOCKINFO info;
		int rs;
		//if(select_socket(sock, 10) <= 0) continue;
		VSL::getsockinfo(link, &info);
		
		if((rs = VSL::recv(sock, buf, SOCKET_BUF_SIZE)) > 0){
			LOG("SOCKS: sending "<<rs<<" bytes to link.");
			VSL::send(link, buf, rs);
		} 
		if(rs == 0 || info.state == VSL::VSOCKET_IDLE){ // client disconnected
			LOG("SOCKS: session has ended!");
			//put_socket_to_cache(get_socket_ip(sock), link);
			VSL::close(link);
			VSL::close(sock);
			it = this->local_clients.erase(it);
			continue;
		} 
		if((rs = VSL::recv(link, buf, SOCKET_BUF_SIZE))>0){
			LOG("SOCKS: sending "<<rs<<" bytes to socks connection!");
			if((VSL::send(sock, buf, rs))<0){
				
			}
		} 
		if(rs < 0 || info.state == VSL::VSOCKET_DISCONNECTED){
			LOG("SOCKS: peer end disconnected.");
			VSL::close(link);
			it = local_clients.erase(it);
			VSL::close(sock);
			continue;
		}
		it++;
	}
}

int SocksService::listen(const URL &url){
	if(VSL::listen(this->local_socket, url)>0){
		LOG("SOCKS: listening on port "<<url.port());
		return 1;
	}
	LOG("SOCKS: failed to listen on "<<url.url());
	return -1;
	
}


