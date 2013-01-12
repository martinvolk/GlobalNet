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
#include <udt.h>
#include <fcntl.h>
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

#define SOCKET_BUF_SIZE 1024

#define SERV_LISTEN_PORT 9000

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
	CON_STATE_UNINITIALIZED,
	CON_STATE_CONNECTING,
	CON_STATE_LISTENING,
	CON_STATE_SSL_HANDSHAKE,
	CON_STATE_RELAY_PENDING,
	CON_STATE_ESTABLISHED,
	CON_STATE_CLOSE_PENDING,
	CON_STATE_DISCONNECTED
}ConnectionState;

typedef int TCPSocket;
typedef int UDPSocket;

// peer to peer connection
struct Connection{
	SSL_CTX *ctx;
	SSL *ssl; // ssl context for the connection
	BIO *read_buf;
	BIO *write_buf;
	bool is_client;
	
	UDTSOCKET socket; // the underlying socket for peer connection
	char host[NI_MAXHOST];
	int port;
	
	ConnectionState state;
	
	// bridging information
	Connection *_next; 
	Connection *_prev;
	
	// this is where the received data will be stored until it can be 
	// validated and converted into a packet that goes into packet_in
	vector<char> _recv_buf; 
	deque<Packet> _recv_packs;
	  
	void 	*data_ptr;
	
	// virtual functions
	int (*connect)(Connection *self, const char *host, uint16_t port);
	int (*send)(Connection *self, const char *data, size_t size);
	int (*recv)(Connection *self, char *data, size_t size);
	int (*sendBlock)(Connection *self, const Packet &pack);
	int (*recvBlock)(Connection *self, Packet &pack);
	int (*listen)(Connection *self, const char *host, uint16_t port);
	Connection* (*accept)(Connection *self);
	void (*run)(Connection *self);
	void (*bridge)(Connection *self, Connection *other);
	void (*close)(Connection *self);
	
	void (*on_data_received)(Connection *self, const char *data, size_t size);
};


struct Command{
	uint16_t code;
	uint16_t source_command;
	uint16_t data_length;
	
	void operator=(const Command& other){
		code = other.code;
	}
}; 


struct Packet{
	Command cmd;
	vector<char> data;
	vector<char> _tbuf;
	
	// private data
	Connection *source;
	
	Packet(){
		cmd.code = -1;
		source = 0;
	}
	
	Packet(const Packet &other){
		memcpy(&cmd, &other.cmd, sizeof(cmd));
		data = other.data;
		source = other.source;
	}
	void operator=(Packet &other){
		memcpy(&cmd, &other.cmd, sizeof(cmd));
		cout<<other.data.size()<<endl; 
		data = vector<char>(other.data.begin(), other.data.end());
		source = other.source;
	}
		
	void toVec(vector<char> &dst){
		cmd.data_length = data.size();
		dst.resize(sizeof(Command)+data.size());
		memcpy(&dst[0], &cmd, sizeof(Command));
		memcpy(&dst[sizeof(Command)], &data[0], data.size());
	}
	const char *c_ptr(){
		cmd.data_length = data.size();
		_tbuf.resize(data.size()+sizeof(Command));
		memcpy(&_tbuf[0], &cmd, sizeof(Command));
		memcpy(&_tbuf[sizeof(Command)], &data[0], data.size());
		return &_tbuf[0];
	}
	size_t size(){
		c_ptr();
		return sizeof(Command)+_tbuf.size();
	}
};

struct Network;
/* a link is an implementation of the routing protocol */ 
/** Writing to a link writes data to the connection */
struct Link{
	//LINKADDRESS address; // sha1 hash of the public key 
	// intermediate peers involved in routing the link (chained connection)
	vector<Connection*> nodes; 
	
	// local TCP socket listening for new data to be sent through the link
	int local_socket; 
};

struct Service{
	LINKADDRESS address; // the global address of the service 
	
	ConnectionState state;
	
	// on server side
	vector<Connection*> clients; // client sockets
	vector<Link*> links;
	
	// on client side 
	Link *server_link;  // link through which we can reach the other end
	int local_socket; // socket of the local connections
	map<string, int> local_clients;
	
	Connection *socket;
	Network *net; 
	
	void *data; 
	
	int (*listen)(Service *self, const char *host, uint16_t port);
	void (*run)(Service *self);
};


struct Network{
	Connection *server; 
	vector<Connection*> peers;
	vector<Link*> links;
	vector<Service*> services;
};

struct Application{
	Network net;
};

void SRV_initSOCKS(Service *self);
void SRV_initCONSOLE(Service *self);

int CON_initPeer(Connection *self, bool client = true);
int CON_initSSL(Connection *self, bool client = true);
int CON_initTCP(Connection *self, bool client = true);
int CON_initUDT(Connection *self, bool client = true);
void CON_init(Connection *self, bool client = true);
void CON_shutdown(Connection *self);

Service *NET_createService(Network *net, const char *name);
Connection *NET_createConnection(Network *self, const char *name, bool client);

int tokenize(const string& str,
                      const string& delimiters, vector<string> &tokens);
string errorstring(int e);

#endif
