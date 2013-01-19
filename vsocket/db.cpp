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
private: 
	pthread_mutex_t *lk;
};

#define LOCK(mu) _locker __lk(mu);

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

void PeerDatabase::insert(const Record &data){
	LOCK(mu);
	
	if(data.peer_ip.compare("") == 0)
		return;
	if(data.peer_ip.compare(data.hub_ip) == 0 && 
			data.peer_port == data.hub_port)
		return;
		
	this->db[data.hash().hex()] = data;
}

void PeerDatabase::update(const Record &data){
	LOCK(mu);
	
	//LOG("PDB: update: "<<data.peer_ip);
	map<string, Record>::iterator it = this->db.find(data.hash().hex());
	if(it == this->db.end()) {insert(data); return;}
	(*it).second = data;
}

vector<PeerDatabase::Record> PeerDatabase::random(unsigned int count){
	LOCK(mu);
	
	vector<Record> rand_set;
	rand_set.reserve(this->db.size());
	for(map<string, Record>::iterator it = this->db.begin(); 
			it != this->db.end(); it++){
		//LOG((*it).second.hash().hex());
		rand_set.push_back((*it).second);
	}
	std::random_shuffle(rand_set.begin(), rand_set.end());
	if(rand_set.size()>count) rand_set.resize(count);
	//LOG("PDB: size: "<<rand_set.size());
	return rand_set;
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
					LOG("PDB: purge: deleting record: "<<(*it).second.peer_ip<<":"<<(*it).second.peer_port);
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
