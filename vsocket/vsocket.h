/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#ifndef _VSOCKET_H_
#define _VSOCKET_H_

#include <stdint.h>
#include <cstring>

namespace VSL {
	typedef struct { unsigned char hash[20]; } SHA1Hash;
	typedef int VSOCKET;
	
	#define VSOCKET_DEFAULT_PEER_PORT 9000
	
	typedef enum{
		SOCKET_INTERNAL,
		SOCKET_TCP
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
	
	/** initializes the virtual sockets subsystem. 
	Private and public keys specifies the keys which will be used as
	main keys on this instance of VSL sockets. **/
	int init();
	void shutdown();
	
	int add_peer(const char *host_port);
	
	/** bootstraps the network by connecting to the specified list of peers. 
	There can be any number of initial peers. Once connected, we can use 
	these peers as gateways to access the rest of the network. Peers
	work very much like default gateways in conventional routing. */
	int bootstrap(const char *peers);
	
	/** Allocates a socket and returns it's descriptor **/
	VSOCKET socket(SOCKPROTO proto);
	/** Creates a random tunnel to some peer. You can then use bind() or 
	listen() or connect() on the returned socket. **/
	VSOCKET tunnel(const char *host_port);
	/** 
	Binds an allocated socket to the socket address. The address consists of 
	a public hash of the peer where to bind the socket and a port number. 
	- The function puts the socket into BINDING state and exits immedietly. 
	- Once the socket is bound, it switches state to BOUND. 
	- If the bind operation fails, then the socket goes into ERROR state. 
	**/
	int bind(VSOCKET socket, const char *address);
	int bind(VSOCKET socket, const sockaddr_t *address);
	
	int listen(VSOCKET socket, const char *address);
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
	
	int connect(VSOCKET socket, const char *host, uint16_t port);
	
	void run();
	
	int getsockinfo(VSOCKET sock, SOCKINFO *info);
	
	int close(VSOCKET socket);
	
	void print_stats(int socket);
}

#endif
