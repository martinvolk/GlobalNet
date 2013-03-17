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

/*
#define LOCK_BOTH(mu1, mu2) \
	boost::lock_guard<boost::mutex> __lhs_lock(mu1, boost::defer_lock);\
	boost::lock_guard<boost::mutex> __rhs_lock(mu2, boost::defer_lock);\
	boost::lock(__lhs_lock, __rhs_lock);\
*/


static bool _try_connect(const URL &url){
	struct addrinfo hints, *local = 0, *peer = 0;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	
	if (0 != getaddrinfo(NULL, VSL::to_string(url.port()).c_str(), &hints, &local)){
		ERROR("Could not get address info on local address!");
	}
	
	UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);
	if (0 != getaddrinfo(url.host().c_str(), VSL::to_string(url.port()).c_str(), &hints, &peer)){
		LOG(1,"PDB: peer vetting failed: error getting peer address!"<<url.url());
		goto fail;
	}
	if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
	{
		//LOG(1,"PDB: peer vetting failed on " << host <<":"<<port<<": "<< UDT::getlasterror().getErrorMessage());
		goto fail;
	}
	if(local)freeaddrinfo(local);
	if(peer)freeaddrinfo(peer);
	UDT::close(client);
	return true;
fail:
	freeaddrinfo(local);
	if(peer)freeaddrinfo(peer);
	UDT::close(client);
	return false;
}
/// a thread that ensures the most up to date data in the database. 

static void *_db_worker(void *data){
	PeerDatabase *self = (PeerDatabase*)data;
	self->loop();
	return 0;
}

PeerDatabase::PeerDatabase(){
	running = true;
	pthread_mutex_init(&mu, 0);
	pthread_create(&worker, 0, &_db_worker, this);
}

PeerDatabase::~PeerDatabase(){
	LOG(1,"PDB: stopping threads...");
	running = false;
	void *ret;
	pthread_join(worker, &ret);
}

void PeerDatabase::insert(const Record &_data){
	LOCK(mu,0);
	
//#ifndef DEBUG
	if(blocked.find(_data.peer.host()) != blocked.end())
		return;
//#endif

	Record data = _data;
	if(data.peer.host().compare("") == 0){
		//LOG(1,"PDB: skipping peer: ip is null");
		return;
	}
	if(data.peer.protocol().compare("vsl") != 0){
		ERROR("PDB: trying to add a non VSL url! "<<data.peer.url());
		return;
	}
	if(data.peer.host().compare(data.hub.host()) == 0 && 
			data.peer.port() == data.hub.port()){
		LOG(1,"PDB: skipping peer: ip same as hub!");
		return;
	}
	// comment out this block to disallow local hosts in database
	// (doing so will break localhost testing so use for production)
	if(inet_ip_is_local(inet_get_host_ip(data.peer.host()))){
		//LOG(1,"PDB: skipping peer because it's a local address!");
		return;
	}
	
	data.last_update = time(0);
	//LOG(1,"PDB: adding peer into database: "<<data.peer.ip<<":"<<data.peer.port);
	this->quarantine[data.hash().hex()] = data;
}

void PeerDatabase::update(const Record &_data){
	LOCK(mu,0);
	
	Record data = _data;
	map<string, Record>::iterator it = this->db.find(data.hash().hex());
	if(it == this->db.end()) { 
		UNLOCK(mu,0); 
		
		insert(data); 
		return;
	}
	//LOG(1,"PDB: update: "<<data.peer.ip<<":"<<data.peer.port);
	data.last_update = time(0);
	(*it).second = data;
}

vector<PeerDatabase::Record> PeerDatabase::random(unsigned int count, bool include_nat_peers){
	LOCK(mu,0);
	
	vector<Record> rand_set;
	rand_set.reserve(this->db.size());
	for(map<string, Record>::iterator it = this->db.begin(); 
			it != this->db.end(); it++){
		if((*it).second.peer.port() != SERV_LISTEN_PORT)
			continue;
		//LOG(1,(*it).second.hash().hex()<<": "<<(*it).second.peer.ip<<":"<<(*it).second.peer.port);
		rand_set.push_back((*it).second);
	}
	if(rand_set.size()==0) return rand_set;
	std::random_shuffle(rand_set.begin(), rand_set.end());
	if(rand_set.size()>count) rand_set.resize(count);
	//LOG(1,"PDB: size: "<<rand_set.size());
	return rand_set;
}

string PeerDatabase::to_string(unsigned int count){
	vector<PeerDatabase::Record> rand_set = random(count);
	
	stringstream ss;
	ss<<time(0);
	for(size_t c=0;c< rand_set.size();c++){
		ss<<";"<<rand_set[c].hub.url()<<"|"
			<<rand_set[c].peer.url()<<"|"
			<<rand_set[c].last_update;
	}
	return ss.str();
}

void PeerDatabase::from_string(const string &peers){
	
	vector<string> fields;
		
	tokenize(peers, ";", fields);
	time_t packet_time = atol(fields[0].c_str());
	for(unsigned int c=1;c<fields.size();c++){
		vector<string> parts;
		tokenize(fields[c], "|", parts);
		if(parts.size() != 3){
			ERROR("Invalid format for the list of IPs.");
			return;
		}
		PeerDatabase::Record r; 
		r.hub = URL(parts[0]);
		r.peer = URL(parts[1]);
		r.last_update = time(0) - packet_time + atol(parts[3].c_str());
		
		insert(r);
	}
}

void PeerDatabase::loop(){
	time_t timer1 = 0, timer2 = 0;
	unsigned long usec = 0;
	while(running){
		{
			if((usec % 100) == 0 && LOGLEVEL > 1){
				cout<<"D";
				fflush(stdout);
			}
			usec++;
			
			// test peers that are in quarantine and add them to the database if everything checks out. 
			vector<Record> tmp;
			
			if(time(0) - timer1 > 10){
				LOCK(mu,0);
				LOG(1,"PDB: doing quarantine");
				for(map<string, Record>::iterator it = this->quarantine.begin(); 
						it != this->quarantine.end(); it++) tmp.push_back((*it).second); 
				quarantine.clear();
				UNLOCK(mu,0);
				
				for(vector<Record>::iterator it = tmp.begin(); it != tmp.end(); it++){
					bool reachable = _try_connect((*it).peer);
					
					// add the peer to the database
					if(reachable){
						LOCK(mu,1);
						db[(*it).hash().hex()] = (*it);
						UNLOCK(mu,1);
					}
					usleep(1000);
					if(!running) break;
				}
				timer1 = time(0);
			}
			
			// check peers that are in the database and remove the ones that are unreachable. 
			if(time(0) - timer2 > 5){
				tmp.clear();
				LOCK(mu,2);
				LOG(1,"PDB: doing routine checks..");
				for(map<string, Record>::iterator it = this->db.begin(); 
						it != this->db.end(); it++) tmp.push_back((*it).second); 
				UNLOCK(mu,2);
				
				for(vector<Record>::iterator it = tmp.begin(); it != tmp.end(); it++){
					// try to establish a connection to the peer. 
					bool reachable = _try_connect((*it).peer);
					
					// remove if unreachable and save in offline peers so that we can later reconnect
					if(!reachable){
						LOCK(mu,1);
						LOG(1,"PDB: removing unreachable host: "<<(*it).peer.url());
						db.erase(db.find((*it).hash().hex()));
						offline[(*it).hash().hex()] = (*it);
						UNLOCK(mu,1);
					}
					usleep(1000);
					if(!running) break;
				}
				timer2 = time(0);
			}
			
			// check all offline peers and move the ones that are reachable back into the database
			// (for example if a host temporarily goes offline, we have our little memory here that comes in handy). 
			/*tmp.clear();
			LOCK(mu,4);
			for(map<string, Record>::iterator it = this->offline.begin(); 
					it != this->offline.end(); it++) tmp.push_back((*it).second); 
			UNLOCK(mu,4);
			
			for(vector<Record>::iterator it = tmp.begin(); it != tmp.end(); it++){
				// try to establish a connection to the peer. 
				bool reachable = _try_connect((*it).peer.ip, (*it).peer.port);
				
				// remove if unreachable and save in offline peers so that we can later reconnect
				if(reachable){
					LOCK(mu,1);
					LOG(1,"PDB: host back online, readding: "<<(*it).peer.ip<<":"<<(*it).peer.port);
					offline.erase(offline.find((*it).hash().hex()));
					db[(*it).hash().hex()] = (*it);
					UNLOCK(mu,1);
				}
				sleep(3);
			}*/
		}
		usleep(1000);
	}
	LOG(1,"PDB: main loop exiting..");
}
