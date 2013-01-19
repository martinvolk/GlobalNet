#include "local.h"

void PeerDatabase::insert(const PeerRecord &data){
	if(data.peer_ip.compare("") == 0)
		return;
	if(data.peer_ip.compare(data.hub_ip) == 0 && 
			data.peer_port == data.hub_port)
		return;
		
	this->db[data.hash().hex()] = data;
}

void PeerDatabase::update(const PeerRecord &data){
	//LOG("PDB: update: "<<data.peer_ip);
	map<string, PeerRecord>::iterator it = this->db.find(data.hash().hex());
	if(it == this->db.end()) {insert(data); return;}
	(*it).second = data;
}

vector<PeerRecord> PeerDatabase::random(unsigned int count){
	vector<PeerRecord> rand_set;
	rand_set.reserve(this->db.size());
	for(map<string, PeerRecord>::iterator it = this->db.begin(); 
			it != this->db.end(); it++){
		LOG((*it).second.hash().hex());
		rand_set.push_back((*it).second);
	}
	std::random_shuffle(rand_set.begin(), rand_set.end());
	if(rand_set.size()>count) rand_set.resize(count);
	LOG("PDB: size: "<<rand_set.size());
	return rand_set;
}
void PeerDatabase::purge(){
	for(map<string, PeerRecord>::iterator it = this->db.begin(); 
			it != this->db.end(); ){
		time_t t = time(0);
		if(t-(*it).second.last_update > NET_PEER_PURGE_INTERVAL){
			LOG("PDB: purge: deleting record: "<<(*it).second.peer_ip<<":"<<(*it).second.peer_port);
			this->db.erase(it++);
		}
		else {
			it++;
		}
	}
}
