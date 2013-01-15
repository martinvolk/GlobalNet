#ifndef _GCLIENT_H_
#define _GCLIENT_H_

#include <string>
#ifndef WIN32
   #include <unistd.h>
   #include <cstdlib>
   #include <cstring>
   #include <netdb.h>
  
#else
 #include <winsock2.h>
 #include <ws2tcpip.h>
 #include <wspiapi.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
	
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <arpa/inet.h>
#include <signal.h>
#include <numeric>
#include "udt/udt.h"
#include <fcntl.h>
#include <math.h>
#include "cc.h"
#include "optionparser.h"

using namespace std;

#define LOG(msg) { cout << "["<<__FILE__<<" line: "<<__LINE__<<"] "<<msg << endl; }
#define ERROR(msg) { cout << "[ERROR] "<<msg << endl; }

#define SOCK_ERROR(what) { \
		if ( errno != 0 ) {  \
			fputs(strerror(errno),stderr);  \
			fputs("  ",stderr);  \
		}  \
		fputs(what,stderr);  \
		fputc( '\n', stderr); \
}

#define ARRSIZE(arr) (sizeof(arr)/sizeof(arr[0]))

#define SOCKET_BUF_SIZE 8192

#define SERV_LISTEN_PORT 9000

// maximum simultaneous connections
#define MAX_CONNECTIONS 1024
#define MAX_LINKS 1024
#define MAX_SERVERS 32
#define MAX_SOCKETS 1024
#define MAX_PEERS 1024
#define MAX_PACKET_SIZE 32768
#define MAX_LINK_NODES 16

#define CONNECTION_TIMEOUT 10000

typedef struct linkaddress_t {
	char hash[20];
	
	linkaddress_t(){
		memset(hash, 0, sizeof(hash));
	}
	linkaddress_t(const linkaddress_t &other){
		memcpy(hash, other.hash, sizeof(hash));
	}
	
	bool operator < (const linkaddress_t &other) const{ 
		char str[21];
		char local[21];
		memcpy(local, this->hash, sizeof(local));
		memcpy(str, other.hash, sizeof(hash));
		str[20] = 0;
		local[20] = 0;
		return strcmp(str, local);
	}
	bool operator == (const linkaddress_t &other) const{
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
	string str(){
		return hex();
	}
} LINKADDRESS;

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
	bool is_client;
	
	UDTSOCKET socket; // the underlying socket for peer connection
	char host[NI_MAXHOST];
	int port;
	
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
	//int (*recvBlock)(Connection &self, Packet &pack);
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
	//LINKADDRESS address; // sha1 hash of the public key 
	// intermediate peers involved in routing the link (chained connection)
	Connection *nodes[MAX_LINK_NODES]; 
	uint length;
	
	Network *net; // parent network
};

struct Service{
	bool initialized;
	
	LINKADDRESS address; // the global address of the service 
	
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
};

struct Network{
	Connection *server; 
	Connection sockets[MAX_SOCKETS];
	Link links[MAX_LINKS];
	Service services[MAX_SERVERS];
	Peer peers[MAX_PEERS];
};

struct Application{
	Network net;
};

void SRV_initSOCKS(Service &self);
void SRV_initCONSOLE(Service &self);
Connection *SRV_accept(Service &self);

int CON_initPeer(Connection &self, bool client = true, Connection *output = 0);
int CON_initSSL(Connection &self, bool client = true);
int CON_initTCP(Connection &self, bool client = true);
void CON_initLINK(Connection &self, bool client = true);
int CON_initUDT(Connection &self, bool client = true);
void CON_initBRIDGE(Connection &self, bool client = true);
void CON_init(Connection &self, bool client = true);
void CON_shutdown(Connection &self);

int NET_init(Network &self);
Connection *NET_connect(Network &self, const char *hostname, int port);
int NET_run(Network &self);
void NET_shutdown(Network &self);

Connection *NET_allocConnection(Network &self);
Connection *NET_createConnection(Network &self, const char *name, bool client);
Connection *NET_createTunnel(Network &self, const string &host, uint16_t port);
Service *NET_createService(Network &self, const char *name);

Service &self_createService(Network &self, const char *name);
Connection &self_createConnection(Network &self, const char *name, bool client);

double milliseconds();
int tokenize(const string& str,
                      const string& delimiters, vector<string> &tokens);
string errorstring(int e);

#endif
