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

#include <udt.h>
#include <math.h>

using namespace std;

#define LOG(msg) { cout << "["<<__FILE__<<" line: "<<__LINE__<<"] "<<msg << endl; }
#define ERROR(msg) { cout << "["<<__FILE__<<" line: "<<__LINE__<<"] "<< "[ERROR] "<<msg << endl; }

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
// send a handful of peers to each connected peer every 10 seconds. 
#define NET_PEER_LIST_INTERVAL 5
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
	RELAY_DISCONNECT,
	
	/** DHT MESSAGES */
	DHT_STOR, 
	DHT_RETR, 
	
	CMD_REG_LINK, /// register a link on the other peer
	CMD_UNREG_LINK, /// unregister a link 
}ConnectionMessage;

typedef enum{
	CON_STATE_UNINITIALIZED		= 0,
	CON_STATE_INITIALIZED			= 1<<1,
	CON_STATE_CONNECTING			= 1<<2,
	CON_STATE_LISTENING				= 1<<3,
	CON_STATE_SSL_HANDSHAKE		= 1<<4,
	CON_STATE_RELAY_PENDING		= 1<<5,
	CON_STATE_ESTABLISHED			= 1<<6,
	CON_STATE_WAIT_CLOSE			= 1<<8,
	CON_STATE_DISCONNECTED		= 1<<9
}ConnectionState;

#define CON_STATE_NOT_CONNECTED (CON_STATE_UNINITIALIZED|\
				CON_STATE_INITIALIZED|CON_STATE_CONNECTING|\
				CON_STATE_LISTENING|CON_STATE_SSL_HANDSHAKE|\
				CON_STATE_RELAY_PENDING)
#define CON_STATE_CONNECTED (CON_STATE_ESTABLISHED)
#define CON_STATE_INVALID (CON_STATE_WAIT_CLOSE|CON_STATE_DISCONNECTED)

typedef enum{
	NODE_NONE=0,
	NODE_TCP,
	NODE_UDT,
	NODE_SSL,
	NODE_PEER,
	NODE_LINK
}NodeType; 

typedef int TCPSocket;
typedef int UDPSocket;

struct Network;
    
// peer to peer connection
struct Connection{
	bool initialized;
	NodeType type;
	
	Network *net;
	
	SSL_CTX *ctx;
	SSL *ssl; // ssl context for the connection
	
	/// input read write buffers
	BIO *in_read;
	BIO *in_write;
	
	/// output read write buffers
	BIO *read_buf;
	BIO *write_buf;
	
	bool server_socket;
	
	UDTSOCKET socket; // the underlying socket for peer connection
	string host;
	uint16_t port;
	
	double timer; 
	
	ConnectionState state;
	
	// bridging information
	Connection *_output; 
	Connection *_input;
	
	// this is where the received data will be stored until it can be 
	// validated and converted into a packet that goes into packet_in
	vector<char> _recv_buf; 
	deque<Packet> _recv_packs;
	  
	void 	*data_ptr;
	
	// virtual functions
	int (*connect)(Connection &self, const char *host, uint16_t port);
	int (*send)(Connection &self, const char *data, size_t size);
	int (*recv)(Connection &self, char *data, size_t size);
	int (*sendCommand)(Connection &self, ConnectionMessage cmd, const char *data, size_t size);
	int (*recvCommand)(Connection &self, Packet *pack);
	int (*listen)(Connection &self, const char *host, uint16_t port);
	Connection* (*accept)(Connection &self);
	void (*run)(Connection &self);
	void (*peg)(Connection &self, Connection *other);
	void (*close)(Connection &self);
}; 


struct PacketHeader{
	uint16_t code;
	uint16_t source_command;
	uint16_t size;
}; 


struct Packet{
	PacketHeader cmd;
	char data[MAX_PACKET_SIZE];
	
	// private data
	Connection *source;
	
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
struct Link{
	bool initialized;
	//SHA1Hash address; // sha1 hash of the public key 
	// intermediate peers involved in routing the link (chained connection)
	Connection *nodes[MAX_LINK_NODES]; 
	uint length;
	
	Network *net; // parent network
};

struct Service{
	bool initialized;
	
	SHA1Hash address; // the global address of the service 
	
	ConnectionState state;
	
	// on server side
	Connection *clients[MAX_SOCKETS]; // client sockets
	Link *links[MAX_LINKS];
	
	// on client side 
	Link *server_link;  // link through which we can reach the other end
	int local_socket; // socket of the local connections
	vector< pair<int, Connection*> > local_clients;
	map<string, void*> _cache;
	
	Connection *socket;
	Network *net; 
	
	void *data; 
	
	int (*listen)(Service &self, const char *host, uint16_t port);
	void (*run)(Service &self);
};

struct Peer{
	bool initialized;
	Connection *socket;
	string listen_port;
	
	time_t last_peer_list_submit; 
};

/** this structure holds public inforamtion that is available about the router. 
most of this information can be double checked, so no reason to spoof it. 
**/
struct RouterInfo{
	// actual interface address on which the router is listening. 
	sockaddr_in address;
	
	// ports that the router supports listening for incoming connections on. 
	uint16_t listen_start_port;
	uint16_t listen_interval; // number of ports from the start port. 
}; 


struct PeerRecord{
	string hub_ip;
	int hub_port;
	string peer_ip;
	int peer_port;
	time_t last_update; 
	bool is_local;
	
	PeerRecord(){
		hub_ip = "0.0.0.0";
		peer_ip = "0.0.0.0";
		hub_port = peer_port = 0;
		last_update = 0;
	}
	PeerRecord(const PeerRecord &other){
		this->hub_ip = other.hub_ip;
		this->hub_port = other.hub_port;
		this->peer_ip = other.peer_ip;
		this->peer_port = other.peer_port;
		this->last_update = other.last_update;
		this->is_local = other.is_local;
	}
	
	SHA1Hash hash() const{
		SHA1Hash ret;
		stringstream ss;
		ss<<hub_ip<<hub_port<<peer_ip<<peer_port; 
		ret.from_string(ss.str());
		return ret;
	}
  bool operator<(const PeerRecord &other) const {
		return this->hash().hex().compare(other.hash().hex()) < 0;
	}
};

class PeerDatabase{
public:
	void insert(const PeerRecord &data);
	void update(const PeerRecord &data);
	vector<PeerRecord> random(unsigned int count);
	void purge();
	
	map<string, PeerRecord> db;
};

struct Network{
	Connection *server; 
	Connection sockets[MAX_SOCKETS];
	Link links[MAX_LINKS];
	Service services[MAX_SERVERS];
	Peer peers[MAX_PEERS];
	
	PeerDatabase peer_db;
};

struct Application{
	Network net;
};

void SRV_initSOCKS(Service &self);
void SRV_initCONSOLE(Service &self);
Connection *SRV_accept(Service &self);

int CON_initPeer(Connection &self, Connection *output = 0);
int CON_initSSL(Connection &self);
int CON_initTCP(Connection &self);
void CON_initLINK(Connection &self);
int CON_initUDT(Connection &self);
void CON_initBRIDGE(Connection &self);
void CON_init(Connection &self);
void CON_shutdown(Connection &self);

int NET_init(Network &self);
Connection *NET_connect(Network &self, const char *hostname, int port);
int NET_run(Network &self);
void NET_shutdown(Network &self);

Connection *NET_allocConnection(Network &self);
Connection *NET_createConnection(Network &self, const char *name);
Connection *NET_createLink(Network &self, const string &path);
Connection *NET_createTunnel(Network &self, const string &host, uint16_t port);
Service *NET_createService(Network &self, const char *name);

Service &self_createService(Network &self, const char *name);
Connection &self_createConnection(Network &self, const char *name, bool client);

bool inet_ip_is_local(const string &ip);
string inet_get_host_ip(const string &hostname);

double milliseconds();
int tokenize(const string& str,
                      const string& delimiters, vector<string> &tokens);
string errorstring(int e);

#endif
