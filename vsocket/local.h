/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#ifndef _GCLIENT_H_
#define _GCLIENT_H_

#include <string>
#ifndef WIN32
	#include <unistd.h>
	#include <cstdlib>
	#include <cstring>
	#include <netdb.h>
	#include <arpa/inet.h>
	#include <sys/time.h>
	#include <signal.h>
	#include <fcntl.h>
#else
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <wspiapi.h>
#endif

/// openssl
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
	
/// stl 
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <string>
#include <vector>
#include <list>
#include <deque>
#include <map>
#include <set>
#include <numeric>

/// boost
//#include <boost/shared_ptr.hpp>
//#include <boost/thread.hpp>

#include <udt.h>
#include <math.h>

using namespace std;

//#define LOG(msg) {}
#define LOG(msg) { cout << "["<<__FILE__<<" line: "<<__LINE__<<"] "<<msg << endl; }
#define INFO(msg) { cout << "["<<time(0)<<"] "<<msg << endl; }
#define ERROR(msg) { cout << "["<<__FILE__<<" line: "<<__LINE__<<"] "<< "[ERROR] =========> "<<msg << endl; }

#define SOCK_ERROR(what) { \
		if ( errno != 0 ) {  \
			fputs(strerror(errno),stderr);  \
			fputs("  ",stderr);  \
		}  \
		fputs(what,stderr);  \
		fputc( '\n', stderr); \
}

#define ARRSIZE(arr) (unsigned long)(sizeof(arr)/sizeof(arr[0]))

#define SOCKET_BUF_SIZE 8192

#define SERV_LISTEN_PORT 9000
#define CLIENT_BIND_PORT 9001

// send a handful of peers to each connected peer every 10 seconds. 
#define NET_PEER_LIST_INTERVAL 10
// remove peers from the list if they have not been updated for one minute. 
#define NET_PEER_PURGE_INTERVAL 30


// maximum simultaneous connections
#define MAX_CONNECTIONS 1024
#define MAX_LINKS 1024
#define MAX_SERVERS 32
#define MAX_SOCKETS 1024
#define MAX_PEERS 1024
#define MAX_PACKET_SIZE 32768
#define MAX_LINK_NODES 16

#define CONNECTION_TIMEOUT 10000

class SHA1Hash {
private: 
	char hash[20];
public: 
	SHA1Hash(){
		memset(hash, 0, sizeof(hash));
	}
	SHA1Hash(const SHA1Hash &other){
		memcpy(hash, other.hash, sizeof(hash));
	}
	
	bool operator < (const SHA1Hash &other) const{ 
		char str[21];
		char local[21];
		memcpy(local, this->hash, sizeof(local));
		memcpy(str, other.hash, sizeof(hash));
		str[20] = 0;
		local[20] = 0;
		return strcmp(str, local);
	}
	bool operator == (const SHA1Hash &other) const{
		return memcmp(this->hash, other.hash, sizeof(hash));
	}
	void fromString(string source){
		static int nibbles[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };
    std::vector<unsigned char> retval;
    for (std::string::const_iterator it = source.begin(); it < source.end(); it += 2) {
        unsigned char v = 0;
        if (std::isxdigit(*it))
            v = nibbles[std::toupper(*it) - '0'] << 4;
        if (it + 1 < source.end() && std::isxdigit(*(it + 1)))
            v += nibbles[std::toupper(*(it + 1)) - '0'];
        retval.push_back(v);
    }
    memcpy(&hash, &retval[0], sizeof(hash));
	}
	std::string hex() const 
	{
			std::ostringstream os;
			os.fill('0');
			os<<std::hex;
			for(const char * ptr=hash;ptr<hash+sizeof(hash);ptr++){
				unsigned int part = ((unsigned int)*ptr) & 0xff;
				os<<std::setw(2)<<part;
			}
			return os.str();
	}
	void from_string(const string &str){
		SHA1((unsigned char*)str.c_str(), str.length(), (unsigned char*)hash);
	}
	string str(){
		return hex();
	}
};

struct Packet;


typedef enum {
	REL_PROTO_INTERNAL_CLIENT = 0, // establishes a simple message connection to another peer
	REL_PROTO_INTERNAL_SERVER,
	REL_PROTO_TCP, // establishes an outgoing TCP connection from relay
	REL_RPOTO_UDP // establishes an outgoing UDP connection from relay
}RelayProtocol;

typedef enum{
	REL_ERR_CON_FAILED,
	REL_ERR_TIMEOUT, // connection has timed out
	REL_ERR_UNKNOWN_HOST, 
}ConnectionError;

typedef enum {
	CMD_ASK = 1,
	CMD_DATA,
	CMD_TEST,
	/// arg: [linkaddress_t] specifying address of the link to check
	CMD_CAN_ROUTE,
	CMD_GET_PEER_LIST,
	CMD_PEER_LIST, // list of active peers. (peer:port,peer2:port.. etc)
	/** relay messages **/
	RELAY_CONNECT, /// [host:port] REL_PROTO_* connect to another host
	RELAY_CONNECT_OK, /// sent by relay upon success. 
	RELAY_ERROR, /// [REL_ERR_*] sent by relay upon error. 
	RELAY_DATA,
	RELAY_PAIR, /// request to pair us with another peer. Relay replies with RELAY_PAIR_RZ_CONNECT
	RELAY_PAIR_RZ_CONNECT, /// supplies IP address to the other peer for a rendezvous connection 
	RELAY_DISCONNECT,
	
	/** DHT MESSAGES */
	DHT_STOR, 
	DHT_RETR, 
	
	CMD_REG_LINK, /// register a link on the other peer
	CMD_UNREG_LINK, /// unregister a link 
}NodeMessage;

typedef enum{
	CON_STATE_UNINITIALIZED		= 0,
	CON_STATE_INITIALIZED			= 1<<1,
	CON_STATE_CONNECTING			= 1<<2,
	CON_STATE_LISTENING				= 1<<3,
	CON_STATE_SSL_HANDSHAKE		= 1<<4,
	CON_STATE_RELAY_PENDING		= 1<<5,
	CON_STATE_ESTABLISHED			= 1<<6,
	CON_STATE_IDLE						= 1<<7,
	CON_STATE_WAIT_CLOSE			= 1<<8,
	CON_STATE_DISCONNECTED		= 1<<9
}ConnectionState;

#define CON_STATE_NOT_CONNECTED (CON_STATE_UNINITIALIZED|\
				CON_STATE_INITIALIZED|CON_STATE_CONNECTING|\
				CON_STATE_LISTENING|CON_STATE_SSL_HANDSHAKE|\
				CON_STATE_RELAY_PENDING)
#define CON_STATE_CONNECTED (CON_STATE_ESTABLISHED | CON_STATE_IDLE)
#define CON_STATE_INVALID (CON_STATE_WAIT_CLOSE|CON_STATE_DISCONNECTED)

typedef enum{
	NODE_NONE=0,
	NODE_TCP,
	NODE_UDT,
	NODE_SSL,
	NODE_PEER,
	NODE_LINK,
	NODE_BRIDGE
}NodeType; 

typedef int TCPSocket;
typedef int UDPSocket;

struct Network;
bool inet_ip_is_local(const string &ip);
string inet_get_host_ip(const string &hostname);
vector< pair<string, string> > inet_get_interfaces();

double milliseconds();
int tokenize(const string& str,
                      const string& delimiters, vector<string> &tokens);
string errorstring(int e);

// a connection node
class Node{
public:
	Node();
	virtual ~Node();
	
	NodeType type;
	
	/// input read write buffers
	BIO *in_read;
	BIO *in_write;
	
	/// output read write buffers
	BIO *read_buf;
	BIO *write_buf;
	
	bool server_socket;
	
	string host;
	uint16_t port;
	
	double timer; 
	
	int state;
	
	// bridging information
	Node *_output; 
	Node *_input;
	
	// this is where the received data will be stored until it can be 
	// validated and converted into a packet that goes into packet_in
	vector<char> _recv_buf; 
	deque<Packet> _recv_packs;
	  
	static Node *createNode(const char *name);
	
	// virtual functions
	virtual int connect(const char *host, uint16_t port);
	virtual int send(const char *data, size_t size);
	virtual int recv(char *data, size_t size);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size);
	virtual int recvCommand(Packet *pack);
	virtual int listen(const char *host, uint16_t port);
	virtual Node* accept();
	virtual void run();
	virtual void peg(Node *other);
	virtual void close();
	virtual void set_output(Node *other);
	virtual void set_input(Node *other);
	virtual Node* get_output();
	virtual Node* get_input();
	
private: 
	// guard against assignments (we would need to implement a proper copy constructor later)
	Node &operator=(const Node &other){ return *this; }
}; 

class VSLNode : public Node{
public:
	VSLNode(Node *next);
	~VSLNode();
	
	virtual int connect(const char *host, uint16_t port);
	virtual int send(const char *data, size_t size);
	virtual int recv(char *data, size_t size);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size);
	virtual int recvCommand(Packet *pack);
	virtual int listen(const char *host, uint16_t port);
	virtual Node* accept();
	virtual void run();
	virtual void peg(Node *other);
	virtual void close();
	
	virtual void set_output(Node *other);
	virtual void set_input(Node *other);
	virtual Node* get_output();
	virtual Node* get_input();
private:
	void _handle_packet(const Packet &packet);
};

class SSLNode : public Node{
public:
	SSLNode();
	~SSLNode();
	
	virtual int connect(const char *host, uint16_t port);
	virtual int send(const char *data, size_t size);
	virtual int recv(char *data, size_t size);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const char *host, uint16_t port);
	virtual Node* accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
private: 
	void _init_ssl_socket(bool server_socket);
	SSL_CTX *ctx;
	SSL *ssl; 
};

class TCPNode : public Node{
public:
	TCPNode();
	~TCPNode();

	virtual int connect(const char *host, uint16_t port);
	virtual int send(const char *data, size_t size);
	virtual int recv(char *data, size_t size);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const char *host, uint16_t port);
	virtual Node* accept();
	virtual void run();
	virtual void peg(Node *other);
	virtual void close();
private:
	int socket;
};

class UDTNode : public Node{
public:
	UDTNode();
	~UDTNode();
	
	virtual int connect(const char *host, uint16_t port);
	virtual int send(const char *data, size_t size);
	virtual int recv(char *data, size_t size);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const char *host, uint16_t port);
	virtual Node* accept();
	virtual void run();
	virtual void peg(Node *other);
	virtual void close();
private:
	UDTSOCKET socket;
};

class BridgeNode : public Node{
public:
	BridgeNode();
	
	virtual int connect(const char *host, uint16_t port);
	virtual int send(const char *data, size_t size);
	virtual int recv(char *data, size_t size);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const char *host, uint16_t port);
	virtual Node* accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
};

class LinkNode : public Node{
public:
	LinkNode();
	~LinkNode();
	
	virtual int connect(const char *host, uint16_t port);
	virtual int send(const char *data, size_t size);
	virtual int recv(char *data, size_t size);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const char *host, uint16_t port);
	virtual Node* accept();
	virtual void run();
	virtual void peg(Node *other);
	virtual void close();
};

struct PacketHeader{
	uint16_t code;
	uint16_t source_command;
	uint16_t size;
}; 


class Packet{
public:
	class Header{
		uint16_t code;
		uint16_t source_command;
		uint16_t size;
	};

	PacketHeader cmd;
	char data[MAX_PACKET_SIZE];
	
	// private data
	Node *source;
	
	Packet(){
		cmd.code = -1;
	}
	
	Packet(const Packet &other){
		memcpy(&cmd, &other.cmd, sizeof(cmd));
		memcpy(data, other.data, sizeof(data));
		source = other.source;
	}
	void operator=(Packet &other){
		memcpy(&cmd, &other.cmd, sizeof(cmd));
		memcpy(data, other.data, sizeof(data));
		source = other.source;
	}
	const char *c_ptr() const{
		return (char*)&cmd;
	}
	size_t size() const {
		return cmd.size+sizeof(PacketHeader);
	}
};

struct Network;
/* a link is an implementation of the routing protocol */ 
/** Writing to a link writes data to the connection */
class Link{
public:
	bool initialized;
	//SHA1Hash address; // sha1 hash of the public key 
	// intermediate peers involved in routing the link (chained connection)
	vector<Node*> nodes; 
	
	Network *net; // parent network
};


typedef enum{
	CAN_DO_NOTHING = 0,
	CAN_ACCEPT_CONNECTIONS 	= 1<<0, // the router can accept connections on it's public IP
	CAN_CONNECT_OUTGOING		= 1<<1, // the router can establish outgoing connections
}PeerCapability; 

struct PeerAddress{
public:
	PeerAddress():ip("0.0.0.0"), port(0){}
	PeerAddress(const string &_ip, uint16_t _port):ip(_ip), port(_port){}
	bool is_local(){ return inet_ip_is_local(ip); }
	bool is_valid(){ return port != 0 && ip.compare("0.0.0.0") != 0; }
	string ip;
	uint16_t port;
};

// info that is sent over the network 
struct PeerInfo{
	PeerAddress listen_address;
	PeerCapability caps; 
};

class PeerDatabase{
public:
	struct Record{
		PeerAddress hub;		// address to the peer we received this record from (ie the hub)
		PeerAddress peer;	// address of the peer
		PeerCapability caps; // capabilities of this peer 
		time_t last_update; // last time this record has been updated 
		
		Record():
			hub("0.0.0.0", 0),
			peer("0.0.0.0", 0),
			last_update(0){
				
		}
		Record(const Record &other){
			this->hub = other.hub;
			this->peer = other.peer;
			this->last_update = other.last_update;
		}
		Record &operator=(const Record &other){
			this->hub = other.hub;
			this->peer = other.peer;
			last_update = other.last_update;
			return *this;
		}
		SHA1Hash hash() const{
			SHA1Hash ret;
			stringstream ss;
			ss<<hub.ip<<hub.port<<peer.ip<<peer.port; 
			ret.from_string(ss.str());
			return ret;
		}
		bool operator<(const Record &other) const {
			return this->hash().hex().compare(other.hash().hex()) < 0;
		}
	};

	PeerDatabase(); 
	~PeerDatabase();
	
	void insert(const Record &data);
	void update(const Record &data);
	vector<Record> random(unsigned int count, bool include_nat_peers = false);
	string to_string(unsigned int count);
	void from_string(const string &str);
		
	void loop();
private: 
	bool running;
	pthread_t worker;
	pthread_mutex_t mu;
	
	map<string, Record> quarantine; 
	map<string, Record> db;
	map<string, Record> offline; 
};

class Network{
public:
	Network();
	~Network();
	
	
	LinkNode *createLink(const string &path);
	LinkNode *createTunnel(const string &host, uint16_t port);
	LinkNode *createCircuit(unsigned int length = 3);
	void connect(const char *hostname, int port);
	void run();
	
	VSLNode *server; 
	
	// list of currently active outgoing links
	vector<Link*> links;
	
	//Peer *createPeer();
	
	PeerDatabase peer_db;
	
	class PeerListener{
		public:
		virtual void handlePacket(const Packet &pack) = 0;
	};
	
	class Peer{
	public:
		Peer(VSLNode *socket){
			this->socket = socket;
		}
		~Peer();
		void run();
		void sendPeerList(const vector<PeerDatabase::Record> &peers);
		bool is_connected();
		bool is_disconnected();
	
		VSLNode *socket;
		PeerAddress listen_addr;
		PeerListener *listener;
		bool peer_info_received;
		time_t last_peer_list_submit; 
	};
	
	list<Peer*> peers;
private:
	
	Peer* getRandomPeer();
	void _handle_command(Node *source, const Packet &pack);
	
};

/*
Connection *NET_connect(Network &self, const char *hostname, int port);
int NET_run(Network &self);
void NET_shutdown(Network &self);

Connection *NET_allocConnection(Network &self);
Connection *NET_createConnection(Network &self, const char *name);
Connection *NET_createLink(Network &self, const string &path);
Connection *NET_createTunnel(Network &self, const string &host, uint16_t port);
Service *NET_createService(Network &self, const char *name);

Service &self_createService(Network &self, const char *name);
_createConnection(Network &self, const char *name, bool client);
*/


#endif
