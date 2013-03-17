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
#include <memory>
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

#define LOG(lev, msg) { if(lev <= LOGLEVEL) cout << "["<<__FILE__<<" line: "<<__LINE__<<",\t"<<\
				(unsigned int)pthread_self()<<"]\t"<<msg << endl; \
				fflush(stdout); }

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
	
	CMD_CONNECT_RZ_REQUEST,
	CMD_CONNECT_RZ_INIT,
	
	CMD_REMOTE_LISTEN,
	CMD_REMOTE_LISTEN_SUCCESS,
	CMD_REMOTE_LISTEN_CLOSE,
	CMD_REMOTE_LISTEN_CLIENT_CONNECTED,
	CMD_REMOTE_LISTEN_CLIENT_DISCONNECTED,
	CMD_REMOTE_LISTEN_DATA,
	
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
	vector<char> data;
	
	Packet(){
		cmd.code = -1;
		cmd.size = 0;
	}
	Packet(NodeMessage code, const char *buf, size_t size, const string &tag){
		cmd.code = code;
		cmd.hash.from_hex_string(tag);
		this->data.resize(size);
		cmd.size = data.size();
		memcpy(&this->data[0], buf, size);
	}
	Packet(const Packet &other){
		cmd = other.cmd;
		data = other.data;
	}
	void operator=(const Packet &other){
		cmd = other.cmd;
		data = other.data;
	}
	/*
	const char *c_ptr() const{
		return (char*)&cmd;
	}*/
	size_t size() const {
		return data.size()+sizeof(PacketHeader);
	}
};

class BufferInterface{
public:
	virtual int recv(char *data, size_t size, size_t minsize = 0) const = 0;
	virtual int send(const char *data, size_t size)= 0;
	virtual int recvOutput(char *data, size_t size, size_t minsize = 0) const {return 0;};
	virtual int sendOutput(const char *data, size_t size) {return 0;};
	virtual size_t input_pending() const = 0;
	virtual size_t output_pending() const = 0;
};

class Buffer : public BufferInterface{
	public:
		Buffer();
		virtual ~Buffer();
		virtual int recv(char *data, size_t size, size_t minsize = 0) const;
		virtual int send(const char *data, size_t size);
		virtual int recvOutput(char *data, size_t size, size_t minsize = 0) const;
		virtual int sendOutput(const char *data, size_t size);
		virtual void flush(); 
		
		virtual size_t input_pending() const ;
		virtual size_t output_pending() const ;
		void clear();
	friend const Buffer &operator<<(vector<char> &data, const Buffer &buf);
	friend Buffer &operator>>(const vector<char> &data, Buffer &buf);
	friend Buffer &operator<<(Buffer &buf, const vector<char> &data);
	friend const Buffer &operator>>(const Buffer &buf, vector<char> &data);
	private:
		BIO *m_pWriteBuf;
		BIO *m_pReadBuf;
		
};
/*
const BufferInterface &operator<<(vector<char> &data, const BufferInterface &buf);
BufferInterface &operator>>(const vector<char> &data, BufferInterface &buf);
BufferInterface &operator<<(BufferInterface &buf, const vector<char> &data);
const BufferInterface &operator>>(const BufferInterface &buf, vector<char> &sdata);
*/
class Node : public BufferInterface{
public:
	Node(weak_ptr<Network> net);
	virtual ~Node();
	
	NodeType type;
	
	bool server_socket;
	
	URL url;
	
	double timer; 
	
	int state;
	
	
	// virtual functions
	virtual int connect(const URL &url);
	virtual int bind(const URL &url) = 0;
	virtual int send(const char *data, size_t maxsize) = 0;
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const = 0;
	virtual int sendCommand(const Packet &data) {return 0;}
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	virtual void peg(Node *other);
	virtual void close();
	
	virtual size_t input_pending() const {return 0;};
	virtual size_t output_pending() const {return 0;};
	
	void set_option(const string &opt, const string &val);
	bool get_option(const string &opt, string &res);
protected: 
	weak_ptr<Network> m_pNetwork;
	
private: 
	map<string, string> options;
	
	// guard against assignments (we would need to implement a proper copy constructor later)
	Node &operator=(const Node &other){ return *this; }
}; 

/*
const Node &operator<<(vector<char> &data, const Node &buf);
const Node &operator<<(PacketHeader &head, const Node &buf);
Node &operator>>(const vector<char> &data, Node &buf);
Node &operator>>(const PacketHeader &data, Node &buf);
Node &operator>>(const Packet &data, Node &buf);
Node &operator<<(Node &buf, const vector<char> &data);
const Node &operator>>(const Node &buf, vector<char> &sdata);
*/
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
VSLNode::setOutput(); 
**/ 
class VSLNode : public Node, public std::enable_shared_from_this<VSLNode>{
public:
	friend class Channel; 
	
	VSLNode(weak_ptr<Network> net, unique_ptr<Node> transport_layer);
	virtual ~VSLNode();
	
	virtual int connect(const URL &url);
	virtual int connect(const unique_ptr<Channel> &hub, const URL &peer);
	
	virtual int bind(const URL &url) ;
	virtual int send(const char *data, size_t maxsize);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const;
	
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	virtual int sendCommand(const Packet &pack);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	virtual void close();
	
	/** We create a channel and release it to the caller. **/
	unique_ptr<Channel> createChannel();
	
	//void do_handshake(SocketType type); 
protected: 
	void releaseChannel(const string &tag);
private:
	void finish();
	
	unique_ptr<Node> m_pTransportLayer;
	
	Buffer m_PacketBuf;
	Packet m_CurrentPacket; 
	
	bool m_bPacketReadInProgress;
	bool m_bReleasingChannel;
	
	time_t m_tConnectInitTime;
	
	// weak pointers to the channels
	map<string, Channel* > m_Channels;
	
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
	//SSLNode(weak_ptr<Network> net, unique_ptr<Node> out);
	SSLNode(weak_ptr<Network> net, unique_ptr<Node> out, SocketType type);
	
	virtual ~SSLNode();
	
	virtual int connect(const URL &url);
	virtual int bind(const URL &url);
	virtual int send(const char *data, size_t maxsize);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const;
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
	
	virtual size_t input_pending() const;
	virtual size_t output_pending() const;
		
	
	void do_handshake(); // server/client
	
private: 
	void _init_ssl_socket(bool server_socket);
	void _close_ssl_socket();
	
	unique_ptr<Node> m_pTransportLayer; 
	
	Buffer m_DataBuffer;
	
	SSL_CTX *m_pCTX;
	SSL *m_pSSL; 
	BIO *read_buf;
	BIO *write_buf;
	
	friend const SSLNode &operator>>(const SSLNode &self, Node *other);
	friend SSLNode &operator<<(SSLNode &, Node*);
};

/*
const SSLNode &operator>>(const SSLNode &node, Node *other);
SSLNode &operator<<(SSLNode &, Node*);

SSLNode &operator>>(const Packet &pack, SSLNode &buf);
SSLNode &operator<<(PacketHeader &header, const SSLNode &buf);
SSLNode &operator<<(vector<char> &data, const SSLNode &buf);
*/
/** 
A TCP connection node. 

Establishes and maintains an outgoing TCP connection. 
**/
class TCPNode : public Node{
public:
	TCPNode(weak_ptr<Network> net);
	virtual ~TCPNode();

	virtual int connect(const URL &url);
	virtual int bind(const URL &url) {return 0;}
	virtual int recv(char *data, size_t size, size_t minsize = 0) const;
	virtual int send(const char *data, size_t size);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	virtual void close();
private:
	Buffer m_Buffer;
	int socket;
	struct sockaddr_in _socket_addr;
};

/** 
A UDT socket node. 

Establishes and maintains a UDT connection. 
**/
class UDTNode : public Node{
public:
	UDTNode(weak_ptr<Network> net);
	virtual ~UDTNode();
	
	virtual int connect(const URL &url);
	virtual int bind(const URL &url);
	virtual int send(const char *data, size_t maxsize);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const;
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	virtual void close();
private:
	URL m_sBindUrl;
	
	Buffer m_Buffer;
	UDTSOCKET socket;
};

class BridgeNode : public Node{
public:
	BridgeNode(weak_ptr<Network> net, unique_ptr<Node>, unique_ptr<Node>);
	virtual ~BridgeNode();
	
	virtual int connect(const URL &url);
	virtual int bind(const URL &url) {return 0;}
	virtual int send(const char *data, size_t maxsize);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const;
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
	
private:
	unique_ptr<Node> m_pNodeOne, m_pNodeTwo;
};

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
	SocksNode(shared_ptr<Network> net);
	virtual ~SocksNode();
	
	struct socks_t{
		socks_t():version(0),code(0),reserved(0),atype(0){}
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
	virtual int send(const char *data, size_t maxsize);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const;
	virtual int bind(const URL &url) {return 0;}
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	//virtual void peg(Node *other);
	virtual void close();
private: 
	const unique_ptr<TCPNode> listen_socket;
	list< pair<socks_state_t, unique_ptr<Node> > > accept_queue;
	list< pair<time_t, unique_ptr<Node> > > accepted; 
};
/*
class LinkNode : public Node{
public:
	LinkNode(shared_ptr<Network> net);
	virtual ~LinkNode();
	
	virtual int connect(const URL &url);
	virtual int send(const char *data, size_t maxsize, size_t minsize = 0);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0);
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	virtual shared_ptr<Node> accept();
	virtual void run();
	virtual void close();
};
*/
//class MemoryNode;

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

</pre>
**/
class MemoryNode;
class NodeAdapter : public Node{
public:
	NodeAdapter(weak_ptr<Network> net, shared_ptr<BufferInterface> other);
	virtual ~NodeAdapter();
	
	virtual int connect(const URL &url);
	
	
	virtual int recv(char *data, size_t size, size_t minsize = 0) const;
	virtual int send(const char *data, size_t size);
	virtual int recvOutput(char *data, size_t size, size_t minsize = 0) const;
	virtual int sendOutput(const char *data, size_t size);
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int recvCommand(Packet *pack);
	virtual int listen(const URL &url);
	//virtual shared_ptr<Node> accept();
	//virtual void run();
	//virtual void close();
	friend NodeAdapter *operator>>(const vector<char> &data, NodeAdapter *node);
	friend NodeAdapter *operator<<(vector<char> &data, NodeAdapter *node);
private: 
	shared_ptr<BufferInterface> m_pNode;
};
//NodeAdapter *operator>>(const vector<char> &data, NodeAdapter *node);
//NodeAdapter *operator<<(vector<char> &data, NodeAdapter *node);
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
node->setOutput(parent);
// we have to explicitly fire of the handshake. 
node->do_handshake(SOCK_CLIENT);
</pre>
**/
class ChannelRemoteConnection;
class Channel : public Node, public PacketHandler{
	friend class VSLNode;
	friend class ChannelRemoteConnection;
protected:
	Channel(weak_ptr<Network> net, VSLNode* link, const string &tag = "");
public:
	virtual ~Channel();
	
	const string &id() const {return m_sHash;}
	
	// this will connect further at the remote end of connection node
	virtual int connect(const URL &url);
	
	virtual int bind(const URL &url) {return 0;}
	// send and receive data to and from the remote end of the channel (use after you have done a "connect)
	virtual int send(const char *data, size_t maxsize);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const;
	virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	virtual int sendCommand(const Packet &pack);
	virtual bool recvCommand(Packet &pack);
	virtual int listen(const URL &url);
	virtual unique_ptr<Node> accept();
	virtual void run();
	virtual void close();
	
	virtual void handlePacket(const Packet &pack);
	
	// detaches the channel from ext_link
	void detach();
private: 
	void unlinkRemoteConnection(uint32_t tag);
	
	bool m_bDeleteInProgress;
	
	//list<shared_ptr<VSLNode> > m_Peers;
	//list<weak_ptr<Channel> > m_Targets;
	Buffer m_ReadBuffer;
	//shared_ptr<Node> m_pRelay;
	string m_sHash;
	
	unique_ptr<Node> m_pListenSocket;
	map<uint32_t, unique_ptr<Node> > m_ListenClients;
	map<uint32_t, ChannelRemoteConnection*> m_RemoteClients;
	deque<pair<uint32_t, ChannelRemoteConnection*> > m_AcceptQueue;
	
	deque<Packet> m_CommandBuffer;
	
	//unique_ptr<Channel> m_pTarget;
	VSLNode* m_extLink;
};

/**
A virtual connection done through a channel to a remote client 
connected over a listening socket. 
**/

class ChannelRemoteConnection : public Node {
	friend class Channel;
protected:
	ChannelRemoteConnection(weak_ptr<Network> net, Channel* link, uint32_t tag);
public:
	virtual ~ChannelRemoteConnection();
	
	// this will connect further at the remote end of connection node
	//virtual int connect(const URL &url);
	
	virtual int bind(const URL &url) {return 0;}
	// send and receive data to and from the remote end of the channel (use after you have done a "connect)
	virtual int send(const char *data, size_t maxsize);
	virtual int recv(char *data, size_t maxsize, size_t minsize = 0) const;
	//virtual int sendCommand(NodeMessage cmd, const char *data, size_t size, const string &tag);
	//virtual int sendCommand(const Packet &pack);
	//virtual bool recvCommand(Packet &pack);
	//virtual int listen(const URL &url);
	//virtual unique_ptr<Node> accept();
	//virtual void run();
	virtual void close();
	
	void handleData(const char *data, size_t size);
	
	void detach();
private: 
	Channel *m_pChannel;
	uint32_t m_iTag;
	
	Buffer m_ReadBuffer;
	
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
	MemoryNode(weak_ptr<Network> net, shared_ptr<BufferInterface> buffer = shared_ptr<BufferInterface>());
	virtual ~MemoryNode();
	
	int sendOutput(const char *data, size_t size);
	int recvOutput(char *data, size_t size, size_t min=0);
	
	virtual int recv(char *data, size_t size, size_t minsize = 0) const ;
	virtual int send(const char *data, size_t size);
	
	virtual int connect(const URL &url);
	virtual int listen(const URL &url){state = CON_STATE_LISTENING; return 1;}
	virtual void close(){state = CON_STATE_DISCONNECTED;}
	//virtual shared_ptr<Node> accept();
	virtual void run();
private: 
	shared_ptr<BufferInterface> m_pBuffer;
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
	
	shared_ptr<Network> net; // parent network
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

class Network : public std::enable_shared_from_this<Network>{
public:
	Network();
	~Network();
	void init();
	
	unique_ptr<Node> createTunnel(const list<URL> &links);
	unique_ptr<Node> connect(const URL &url);
	void run();
	shared_ptr<Node> createNode(const string &type);
	void free(Node *node);
	shared_ptr<Channel> onChannelConnected(const string &tag); 
	
	void listen(const URL &url);
	
	shared_ptr<VSLNode> server; 
	
	// VSLListener methods
	void onChannelConnected(unique_ptr<Channel> chan);
	
	shared_ptr<PeerDatabase> m_pPeerDb;
	
	map<string, shared_ptr<Node> > m_Peers;
private:
	list<unique_ptr<Channel> > m_Channels;
	list<unique_ptr<BridgeNode> > m_Bridges;
	time_t last_peer_list_broadcast;
	//VSLNode* getRandomPeer();
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
