#include "local.h"

/*
#define LOCK_BOTH(mu1, mu2) \
	boost::lock_guard<boost::mutex> __lhs_lock(mu1, boost::defer_lock);\
	boost::lock_guard<boost::mutex> __rhs_lock(mu2, boost::defer_lock);\
	boost::lock(__lhs_lock, __rhs_lock);\
*/

class _locker{
	public:
	_locker(pthread_mutex_t &lock){
		lk = &lock;
		pthread_mutex_lock(lk);
	}
	~_locker(){
		pthread_mutex_unlock(lk);
	}
	void unlock(){ pthread_mutex_unlock(lk); }
private: 
	pthread_mutex_t *lk;
};

#define LOCK(mu) _locker __lk_##mu(mu);
#define UNLOCK(mu) __lk_##mu.unlock();

/// a thread that ensures the most up to date data in the database. 

static void *_db_worker(void *data){
	PeerDatabase *self = (PeerDatabase*)data;
	self->loop();
	return 0;
}

PeerDatabase::PeerDatabase(){
	running = true;
	pthread_create(&worker, 0, &_db_worker, this);
}

PeerDatabase::~PeerDatabase(){
	LOG("PDB: stopping threads...");
	running = false;
	void *ret;
	pthread_join(this->worker, &ret);
}

void PeerDatabase::insert(const Record &_data){
	LOCK(mu);
	
	Record data = _data;
	if(data.peer.ip.compare("") == 0){
		LOG("PDB: skipping peer: ip is null");
		return;
	}
	if(data.peer.ip.compare(data.hub.ip) == 0 && 
			data.peer.port == data.hub.port){
		LOG("PDB: skipping peer: ip same as hub!");
		return;
	}
	
	data.last_update = time(0);
	LOG("PDB: adding peer into database: "<<data.peer.ip<<":"<<data.peer.port);
	this->db[data.hash().hex()] = data;
}

void PeerDatabase::update(const Record &_data){
	LOCK(mu);
	
	Record data = _data;
	map<string, Record>::iterator it = this->db.find(data.hash().hex());
	if(it == this->db.end()) { 
		UNLOCK(mu); 
		
		insert(data); 
		return;
	}
	//LOG("PDB: update: "<<data.peer.ip<<":"<<data.peer.port);
	data.last_update = time(0);
	(*it).second = data;
}

vector<PeerDatabase::Record> PeerDatabase::random(unsigned int count, bool include_nat_peers){
	LOCK(mu);
	
	vector<Record> rand_set;
	rand_set.reserve(this->db.size());
	for(map<string, Record>::iterator it = this->db.begin(); 
			it != this->db.end(); it++){
		LOG((*it).second.hash().hex());
		if(!include_nat_peers && (*it).second.hub.is_valid())
			continue;
		rand_set.push_back((*it).second);
	}
	if(rand_set.size()==0) return rand_set;
	std::random_shuffle(rand_set.begin(), rand_set.end());
	if(rand_set.size()>count) rand_set.resize(count);
	//LOG("PDB: size: "<<rand_set.size());
	return rand_set;
}

string PeerDatabase::to_string(unsigned int count){
	vector<PeerDatabase::Record> rand_set = random(count);
	
	stringstream ss;
	ss<<time(0);
	for(size_t c=0;c< rand_set.size();c++){
		ss<<";"<<rand_set[c].hub.ip<<":"
			<<rand_set[c].hub.port<<":" 
			<<rand_set[c].peer.ip<<":"
			<<rand_set[c].peer.port<<":"
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
		tokenize(fields[c], ":", parts);
		if(parts.size() < 4){
			ERROR("Invalid format for the list of IPs.");
			return;
		}
		PeerDatabase::Record r; 
		r.hub.ip = parts[0];
		r.hub.port = atoi(parts[1].c_str());
		r.peer.ip = parts[2];
		r.peer.port = atoi(parts[3].c_str()); 
		r.last_update = time(0) - packet_time + atol(parts[4].c_str());
		
		insert(r);
	}
}

void PeerDatabase::loop(){
	while(running){
		{
			LOCK(mu);
			/*
			vector<Record> peers;
			peers.reserve(db.size());
			for(map<string, Record>::iterator it = this->db.begin(); 
					it != this->db.end(); ){ peers.push_back((*it).second); } 
			*/
			/*
			Connection con;	
			con.connect("random route");
			int c = 10;
			while(con.state() != Node::STATE_CONNECTED && c != 0){
				sleep(1);
				c--;
			}
			// success
			if(c){
				// save the record in the valid peers database
			} else{
				// discard
			}*/
			
			for(map<string, Record>::iterator it = this->db.begin(); 
					it != this->db.end(); ){
				time_t t = time(0);
				if(t-(*it).second.last_update > NET_PEER_PURGE_INTERVAL){
					LOG("PDB: purge: deleting record: "<<(*it).second.peer.ip<<":"<<(*it).second.peer.port);
					this->db.erase(it++);
				}
				else {
					it++;
				}
			}
		}
		sleep(1);
	}
	LOG("PDB: main loop exiting..");
}
