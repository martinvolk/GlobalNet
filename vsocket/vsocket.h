/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#ifndef _VSOCKET_H_
#define _VSOCKET_H_

#include <stdint.h>
#include <cstring>
#include <string>

class URL {
public:
		URL():port_(0){}
		URL(const URL &other);
		URL(const std::string &proto, const std::string &host, uint16_t port = 0, const std::string &path = "", const std::string &query = "");
    URL(const std::string& url_s);
    const std::string &protocol() const {return protocol_;}
    const std::string &host() const {return host_;}
    const uint16_t &port() const {return port_;}
    const std::string &path() const {return path_;}
    const std::string &query() const {return query_;}
    const std::string &url() const {return url_;}
private:
    void parse(const std::string& url_s);
private:
		std::string protocol_, host_, path_, query_;
		uint16_t port_;
    std::string url_;
};

namespace VSL {
	typedef struct { unsigned char hash[20]; } SHA1Hash;
	typedef int VSOCKET;
	
	using namespace std;

	#define VSOCKET_DEFAULT_PEER_PORT 9000
	
	typedef enum{
		SOCKET_INTERNAL,
		SOCKET_TCP, 
		SOCKET_SOCKS
	}SOCKPROTO;
	
	struct sockaddr_t{
		SHA1Hash sa_hash;
		SOCKPROTO sa_protocol;
		uint16_t sa_port; 
		sockaddr_t *next; // for a chain of addresses 
	}; 
	
	typedef enum{
		VSOCKET_CONNECTED,
		VSOCKET_IDLE,
		VSOCKET_DISCONNECTED
	}SocketState;
	
	struct SOCKINFO{
		SocketState state;
		bool is_connected;
	};
	
	string to_string( int value );
	
	/** initializes the virtual sockets subsystem. 
	Private and public keys specifies the keys which will be used as
	main keys on this instance of VSL sockets. **/
	int init();
	void shutdown();
	
	int add_peer(const URL &url);
	
	/** bootstraps the network by connecting to the specified list of peers. 
	There can be any number of initial peers. Once connected, we can use 
	these peers as gateways to access the rest of the network. Peers
	work very much like default gateways in conventional routing. */
	int bootstrap(const char *peers);
	
	/** Allocates a socket and returns it's descriptor **/
	VSOCKET socket(SOCKPROTO proto);
	/** Creates a random tunnel to some peer. You can then use bind() or 
	listen() or connect() on the returned socket. **/
	VSOCKET tunnel(const URL &url);
	/** 
	Binds an allocated socket to the socket address. The address consists of 
	a public hash of the peer where to bind the socket and a port number. 
	- The function puts the socket into BINDING state and exits immedietly. 
	- Once the socket is bound, it switches state to BOUND. 
	- If the bind operation fails, then the socket goes into ERROR state. 
	**/
	int bind(VSOCKET socket, const URL &url);
	int bind(VSOCKET socket, const sockaddr_t *address);
	
	int listen(VSOCKET socket, const URL &url);
	/**
	Tries to accept a connection on the socket. 
	Returns: 
	- > 0 socket descriptor if the operation succeeded. 
	- 0 if no connection can currently be accepted. 
	- -1 if there is a socket error. 
	**/
	VSOCKET accept(VSOCKET socket); 

	int send(VSOCKET socket, const char *data, size_t size);
	int recv(VSOCKET socket, char *data, size_t size);
	
	int connect(VSOCKET socket, const URL &url);
	
	void run();
	
	int getsockinfo(VSOCKET sock, SOCKINFO *info);
	bool getsockopt(VSOCKET sock, const string &option, string &dst);
	
	int close(VSOCKET socket);
	
	void print_stats(int socket);
}

#endif
