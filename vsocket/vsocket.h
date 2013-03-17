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

#ifndef _VSOCKET_H_
#define _VSOCKET_H_

#include <stdint.h>
#include <cstring>
#include <string>
#include <vector>
#include <list>

#define LOGLEVEL 3

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
		VSOCKET_CONNECTING,
		VSOCKET_CONNECTED,
		VSOCKET_IDLE,
		VSOCKET_LISTENING,
		VSOCKET_DISCONNECTED
	}SocketState;
	
	struct SOCKINFO{
		SocketState state;
		bool is_connected;
	};
	struct PEERINFO{
		URL url;
		
	};
	string to_string( int value );
	
	/** initializes the virtual sockets subsystem. 
	Private and public keys specifies the keys which will be used as
	main keys on this instance of VSL sockets. **/
	int init();
	void shutdown();
	
	/** Returns a list of peers that you can use to relay your 
	connections. 
	\return number of peers added to buffer
	**/
	int get_peers(vector<PEERINFO> &peers);
	int get_peers_allowing_connection_to(const URL &url, 
					vector<PEERINFO> &peers, unsigned int maxcount); 
	
	/** Allocates a socket and returns it's descriptor **/
	VSOCKET socket();
	
	/** Establishes a direct connection to the specified host **/
	int connect(VSOCKET socket, const URL &url);
	/** Establishes a tunnel to the specified hosts **/
	int connect(VSOCKET socket, const list<URL> &links);
	
	int bind(VSOCKET socket, const URL &url);
	/**
	Puts the socket into listening mode and listens for incoming 
	connections on the specified port. 
	**/
	int listen(VSOCKET socket, const URL &url);
	int listen(VSOCKET socket, const list<URL> &links);
	
	/**
	Accepts a new connection if the is one available. 
	
	\return >0 socket descriptor if the operation succeeded. 
	\return 0 if no connection can currently be accepted. 
	\return -1 if there was an error
	**/
	VSOCKET accept(VSOCKET socket); 

	/** 
	Sends data through the socket channel 
	
	\return numread number of bytes stored in the send buffer if successful.
	\return -1 if there was an error. 
	**/
	int send(VSOCKET socket, const char *data, size_t size);
	/** 
	Receives data from the socket channel 
	
	\return numread number of bytes read if successful.
	\return 0 if no bytes were read
	\return -1 if there was an error. 
	**/
	int recv(VSOCKET socket, char *data, size_t size);
	
	int getsockinfo(VSOCKET sock, SOCKINFO *info);
	bool getsockopt(VSOCKET sock, const string &option, string &dst);
	
	int close(VSOCKET socket);
	
	void print_stats(int socket);
}

#endif
