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
#include <string>
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

#include "vsocket.h"

using namespace std;

// loglevel 1-3 (3 = detailed)
#define LOGLEVEL 1

#define LOG(lev, msg) { if(lev <= LOGLEVEL) cout << "["<<__FILE__<<" line: "<<__LINE__<<",\t"<<\
				(unsigned int)pthread_self()<<"]\t"<<msg << endl; }

#define INFO(msg) { cout << "["<<time(0)<<"] "<<msg << endl; }
#define ERROR(msg) { cout << "["<<__FILE__<<" line: "<<__LINE__<<"]\t\t"<< "[ERROR] =========> "<<msg << endl; }

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
#define MAX_SERVERS 32
#define MAX_SOCKETS 1024
#define MAX_PEERS 1024
#define MAX_PACKET_SIZE 32768
#define MAX_LINK_NODES 16

#define CONNECTION_TIMEOUT 10000

class _locker{
	public:
	_locker(pthread_mutex_t &lock){
		lk = &lock;
		pthread_mutex_lock(lk);
		unlocked = false;
	}
	~_locker(){
		if(!unlocked)
			pthread_mutex_unlock(lk);
	}
	void unlock(){ unlocked = true; pthread_mutex_unlock(lk); }
private: 
	bool unlocked;
	pthread_mutex_t *lk;
};

class _setter{
	public:
	_setter(bool &f){
		flag = &f;
		*flag = true;
	}
	~_setter(){
		*flag = false;
	}
	void reset(){ *flag = false; }
private: 
	bool *flag;
};


#define LOCK(mu, it) _locker __lk_##it(mu);
#define UNLOCK(mu, it) __lk_##it.unlock();
#define SETFLAG(mu, it) _setter __lk_##it(mu);
#define RESETFLAG(mu, it) __lk_##it.reset();

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
	
	bool is_zero(){
		for(unsigned int c=0;c<sizeof(hash); c++)
			if(hash[c] != (char)0) return false;
		return true;
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
	void from_hex_string(string source){
		if(source.length() == 0)
			return;
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
	static SHA1Hash compute(const string &str){
		SHA1Hash hash;
		SHA1((unsigned char*)str.c_str(), str.length(), (unsigned char*)&hash.hash);
		return hash;
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
	CMD_ENCRYPT_BEGIN,
	CMD_OUTBOUND_CONNECT,
	CMD_CHAN_INIT,
	CMD_CHAN_ACK,
	CMD_CHAN_CLOSE, 
	
	/** relay messages **/
	RELAY_CONNECT, /// [host:port] REL_PROTO_* connect to another host
	RELAY_ACK, /// sent by relay upon success. 
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

typedef enum {
	SOCK_NONE,
	SOCK_SERVER,
	SOCK_CLIENT
}SocketType;

class Node; 
class VSLNode;
class RoutingEntry;

struct RoutingEntry{
	RoutingEntry(){}
	RoutingEntry(const RoutingEntry &other): from(other.from), 
		dst_hash(other.dst_hash), to(other.to){}
	RoutingEntry(Node *a, const string &b, Node *c): 
		from(a), dst_hash(b), to(c){}
	Node *from;
	string dst_hash;
	Node *to;
};

class Channel;
typedef int TCPSocket;
typedef int UDPSocket;
typedef map<Channel*, Channel*> ChannelList;
typedef map<Node*, Node*> NodeList;
typedef map<string, VSLNode*> PeerList;
typedef VSLNode Peer;

struct Network;
bool inet_ip_is_local(const string &ip);
string inet_get_host_ip(const string &hostname);
vector< pair<string, string> > inet_get_interfaces();
string inet_get_ip(const string &hostname);

double milliseconds();
int tokenize(const string& str,
                      const string& delimiters, vector<string> &tokens);
string errorstring(int e);
string hexencode(const char *data, size_t size);


class Network;


struct PacketHeader{
	PacketHeader():m_iMagic(0xf0fa){}
	PacketHeader(uint16_t code, uint16_t size, SHA1Hash hash):
		code(code), size(size), hash(hash){}
	bool is_valid(){return m_iMagic == 0xf0fa;}
	uint16_t code;
	uint16_t size;
	SHA1Hash hash; 
	uint16_t m_iMagic;
	char reserved[14];
}; 

class Packet{
public:
	PacketHeader cmd;
	char data[MAX_PACKET_SIZE];
	
	// private data
	Node *source;
	
	Packet(){
		cmd.code = -1;
		cmd.size = 0;
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

/**
Node base class. 
**/
class Node{
public:
	Node(Network *net);
	virtual ~Node();
	
	NodeType type;
	
	/// input read write buffers
	BIO *in_read;
	BIO *in_write;
	
	/// output read write buffers
	BIO *read_buf;
	BIO *write_buf;
	
	bool server_socket;
	
	URL url;
	
	double timer; 
	
	int state;
	
	// bridging information
	Node *_output; 
	Node *_input;
	
	deque<Packet> _recv_packs;
	
	// virtual functions
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	virtual int sendCommand(const Packet &pack);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	virtual void peg(Node *other);
	virtual void close();
	virtual void set_output(Node *other);
	virtual void set_input(Node *other);
	virtual Node* get_output();
	virtual Node* get_input();
	
	void set_option(const string &opt, const string &val);
	bool get_option(const string &opt, string &res);
	
protected: 
	Network *m_pNetwork;
	bool m_bProcessingMainLoop;
	
private: 
	map<string, string> options;
	
	// guard against assignments (we would need to implement a proper copy constructor later)
	Node &operator=(const Node &other){ return *this; }
}; 

/** Packet handler object interface **/
class PacketHandler{
	public: 
	virtual void handlePacket(const Packet &pack) = 0;
};

class SSLNode;
class UDTNode;

/** 
Sets up an encrypted connection with SSL and UDT as underlying 
technologies. To replace the UDT layer with something else call 
VSLNode::set_output(); 
**/ 
class VSLNode : public Node{
public:
	VSLNode(Network *net);
	virtual ~VSLNode();
	
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	virtual int sendCommand(const Packet &pack);
	virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	virtual void close();

	virtual void set_output(Node *other);
	virtual Node* get_output();
	/*
	virtual void set_input(Node *other);
	virtual Node* get_input();*/
	Channel *createChannel();
	void releaseChannel(const Channel *chan);
	int numActiveChannels(){return m_Channels.size();}
	
	void do_handshake(SocketType type); 
private:
	SSLNode *ssl;
	UDTNode *udt;
	
	BIO *m_pPacketBuf;
	
	Packet m_CurrentPacket; 
	bool m_bPacketReadInProgress;
	
	map<string, Channel*> m_Channels;
	
	void _handle_packet(const Packet &packet);
};

/** 
An SSL encryption node. 

Anything that goes in with send() is encrypted and then forwarded to 
the _output node send(). 

Call SSLNode::run() to process accumulated data and send it out to the 
output. 
**/ 
class SSLNode : public Node{
public:
	SSLNode(Network *net);
	SSLNode(Network *net, SocketType type);
	
	virtual ~SSLNode();
	
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
	
	void do_handshake(SocketType type);
	
private: 
	void _init_ssl_socket(bool server_socket);
	void _close_ssl_socket();
	SSL_CTX *ctx;
	SSL *ssl; 
};

/** 
A TCP connection node. 

Establishes and maintains an outgoing TCP connection. 
**/
class TCPNode : public Node{
public:
	TCPNode(Network *net);
	virtual ~TCPNode();

	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	virtual void close();
private:
	int socket;
	struct sockaddr_in _socket_addr;
};

/** 
A UDT socket node. 

Establishes and maintains a UDT connection. 
**/
class UDTNode : public Node{
public:
	UDTNode(Network *net);
	virtual ~UDTNode();
	
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	virtual void close();
private:
	UDTSOCKET socket;
};
/*
class BridgeNode : public Node{
public:
	BridgeNode(Network *net);
	
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
};
*/
/** 
Implements a SOCKS5 socket.

Use this node to listen on a TCP port for incoming SOCKS5 connection. 

Example: 
<pre>
SocksNode *socks = new SocksNode(network); 
socks->listen(URL("tcp://localhost:8000"));
Node *con = socks->accept(); // accepts a new connection 
if(con) { do stuff } 
</pre>
**/
class SocksNode : public Node{
public:
	SocksNode(Network *net);
	virtual ~SocksNode();
	
	struct socks_t{
		unsigned char version;
		unsigned char code;
		unsigned char reserved;
		unsigned char atype;
		char data[256];
	};

	struct socks_state_t{
		int state;
		socks_t socks;
		string host;
		uint16_t port;
		time_t last_event; 
	};
	
	//virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
private: 
	TCPNode *listen_socket;
	list< pair<socks_state_t, Node*> > accept_queue;
	list< pair<time_t, Node*> > accepted; 
};
/*
class LinkNode : public Node{
public:
	LinkNode(Network *net);
	virtual ~LinkNode();
	
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	virtual void close();
};
*/
class MemoryNode;

/**
An adapter node. 

Use this node to convert an output of a node into an input. 

Let's say that you have an SSLNode and you want to send data to this 
node. There is no way to send encrypted data to an ssl node because it 
uses it's _output variable and calls send() on that object when it 
wants to output data. Similarly it calls recv() on the underlying 
output object to read encrypted data form the underlying node. 

The solution is to create a memory node that we set as output of the 
SSLNode. The memory node then provides two function sendOutput() and 
recvOutput() to make it possible to write to it's "output" buffer. 

We then connect the send() of NodeAdapter to sendOutput() of the 
memory node and through this scheme basically in a clean and 
independent way make it possible to write to an input of any other 
node which need only to care about it's _output node and read data 
from it when it wants to read more data. 

Example: 
<pre>
SSLNode *ssl = new SSLNode(network);
NodeAdapter *input = new NodeAdapter(ssl); 

input->send(encrypted_data, size); // sends encrypted block of data to 
the input of ssl node. 
ssl->recv(buffer, size); // reads decrypted data from the SSL node. 

delete input; 
delete ssl;
</pre>
**/
class NodeAdapter : public Node{
public:
	NodeAdapter(Network *net, Node *other);
	virtual ~NodeAdapter();
	
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	//virtual Node* accept();
	//virtual void run();
	//virtual void close();
private: 
	Node *other;
	MemoryNode *memnode;
};

/**
Channel implements a channel interface on a VSLNode. 
A single VSLNode can have many channels that are attached to it and 
communicate with the remote end. A channel always has a remote end 
object on the other side of the connection of VSLNode. 

You create a channel object and attach it to a vsl node like this:
Channel *chan = new Channel(network, vslnode); 

This creates a channel that will be using VSLNode for communication 
and sends a CMD_CHAN_INIT message to the VSLNode on the remote end 
with a randomly generated hash that will be used to identify the 
packets that are addressed to this channel. 

You can then attach another VSL node on top of a Channel to enable 
encryption of the channel data (in the case where you call 
Channel::connect() to connect to another peer - then you always should 
initialize a new encrypted session with that peer prior to sending 
commands to it. This is done like this: 

<pre>
Channel *chan = new Channel(net, vslnode);
// establish an outgoing connection on the remote host
chan->connect(random[c].peer);
// signal that we are starting to encrypt data 
chan->sendCommand(CMD_ENCRYPT_BEGIN, "", 0, "");
// create a new VSLNode and set it's output to the channel. 
VSLNode *node = new VSLNode(this);
node->set_output(parent);
// we have to explicitly fire of the handshake. 
node->do_handshake(SOCK_CLIENT);
</pre>
**/
class Channel : public Node, public PacketHandler{
	friend class VSLNode;
protected:
	Channel(Network *net, VSLNode *link, const string &tag = "");
public:
	virtual ~Channel();
	
	const string &id() const {return m_sHash;}
	
	// this will connect further at the remote end of connection node
	virtual int connect(const URL &url);
	
	// send and receive data to and from the remote end of the channel (use after you have done a "connect)
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	virtual int sendCommand(const Packet &pack);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual Node* accept();
	virtual void run();
	virtual void close();
	
	virtual void handlePacket(const Packet &pack);
private: 
	list<VSLNode*> m_Peers;
	Node *m_pRelay;
	string m_sHash;
	
	Node *m_pTarget;
	VSLNode *m_extLink;
};

/**
A memory based buffer node. 

Used for building intermediate chains. For example the NodeAdapter 
class is using a memory node that it sets as output of another node 
and uses this object as a way to gather output data form another node 
(which can call send() several times in a row). 
**/
class MemoryNode : public Node{
public:
	MemoryNode(Network *net);
	virtual ~MemoryNode();
	
	int sendOutput(const char *data, size_t size, size_t min=0);
	int recvOutput(char *data, size_t size, size_t min=0);
	
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int connect(const URL &url);
	virtual int listen(const URL &url){state = CON_STATE_LISTENING; return 1;}
	virtual void close(){state = CON_STATE_DISCONNECTED;}
	//virtual Node* accept();
	virtual void run();
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

// info that is sent over the network 
struct PeerInfo{
	URL listen_address;
	PeerCapability caps; 
};

class PeerDatabase{
public:
	struct Record{
		URL hub;
		URL peer;
		PeerCapability caps; // capabilities of this peer 
		time_t last_update; // last time this record has been updated 
		
		Record():
			hub("nil://0.0.0.0:0"),
			peer("nil://0.0.0.0:0"),
			last_update(0){
				
		}
		Record(const Record &other):
			hub("nil://0.0.0.0:0"),
			peer("nil://0.0.0.0:0"){
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
			stringstream ss;
			ss<<hub.url()<<"#"<<peer.url();
			return SHA1Hash::compute(ss.str());
		}
		bool operator<(const Record &other) const {
			return this->hash().hex().compare(other.hash().hex()) < 0;
		}
	};

	PeerDatabase(); 
	~PeerDatabase();
	
	void blacklist(const string &ip) { blocked.insert(ip); }
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
	set<string> blocked;
};

class Network{
public:
	Network();
	~Network();
	
	Node *createTunnel(const list<URL> &links);
	Node *connect(const URL &url);
	void run();
	Node *createNode(const string &type);
	void free(Node *node);
	
	void listen(const URL &url);
	
	VSLNode *server; 
	
	// list of currently active outgoing links
	vector<Link*> links;
	
	//Peer *createPeer();
	
	PeerDatabase peer_db;
	
	PeerList peers;
private:
	time_t last_peer_list_broadcast;
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
