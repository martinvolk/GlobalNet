/*********************************************
GClient - GlobalNet P2P client
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#ifndef _GCLIENT_H_
#define _GCLIENT_H_ 

#define DEBUG



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
	
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <numeric>
#include <fcntl.h>
#include <math.h>
#include "optionparser.h"
#include "vsocket/vsocket.h"

using namespace std;


#define LOG(lev,msg) { if(lev <= LOGLEVEL) cout << "["<<__FILE__<<" line: "<<__LINE__<<"] "<<msg << endl; fflush(stdout);}

#define INFO(msg) { cout << "["<<time(0)<<"]\t"<<msg << endl; }
#define ERROR(msg) { cout << "["<<__FILE__<<" line: "<<__LINE__<<"] "<< "[ERROR] "<<msg << endl; }
#define ARRSIZE(arr) (unsigned long)(sizeof(arr)/sizeof(arr[0]))

#define SOCKET_BUF_SIZE 1024

#define SOCK_ERROR(what) { \
		if ( errno != 0 ) {  \
			fputs(strerror(errno),stderr);  \
			fputs("  ",stderr);  \
		}  \
		fputs(what,stderr);  \
		fputc( '\n', stderr); \
}

// maximum simultaneous connections
#define MAX_CONNECTIONS 1024
#define MAX_LINKS 1024
#define MAX_SERVERS 32
#define MAX_SOCKETS 1024


class Service{
public:
	virtual ~Service() {}
	
	// on server side
	vector<VSL::VSOCKET> clients; // client sockets
	vector<VSL::VSOCKET> links;
	
	// on client side 
	VSL::VSOCKET server_link;  // link through which we can reach the other end
	VSL::VSOCKET local_socket; // socket of the local connections
	list< pair<VSL::VSOCKET, VSL::VSOCKET> > local_clients;
	map<string, void*> _cache;
	
	// listening socket
	VSL::VSOCKET socket;
	
	virtual int listen(const URL &url) = 0;
	virtual void run() = 0;
};

class SocksService : public Service{
public:
	SocksService();
	~SocksService();
	virtual int listen(const URL &url);
	virtual void run();
private: 
	class CachePost{
	public:
		CachePost(){socket = 0; last_used = 0;}
		CachePost(VSL::VSOCKET s, time_t t){socket = s; last_used = t;}
		VSL::VSOCKET socket; 
		time_t last_used; 
	};
	typedef map<string, map<VSL::VSOCKET, CachePost> > Cache;
	
	VSL::VSOCKET get_socket_from_cache(const char *ip);
	void put_socket_to_cache(const char *ip, VSL::VSOCKET);
	
	// cache made from client IP and list of currently open sockets. 
	Cache cache; 
};

class ConsoleService : public Service{
	~ConsoleService();
	virtual int listen(const URL &url);
	virtual void run();
};

class SecretService: public Service{
public:
	SecretService();
	virtual ~SecretService();
	
	void addListeningChain(const URL &serviceaddr, const list<URL> &urls, const URL &listenaddr);
	void addConnectionChain(const URL &localaddr, const list<URL> &urls, const URL &remoteaddr);
	
	virtual int listen(const URL &url){};
	virtual void run();
	
private:
	list<pair<VSL::VSOCKET, URL> > m_ListeningChains;
	list<pair<VSL::VSOCKET, VSL::VSOCKET> > m_ActiveChains;
};

struct Application{
	
};

void SRV_initSOCKS(Service &self);
void SRV_initCONSOLE(Service &self);
VSL::VSOCKET SRV_accept(Service &self);

int tokenize(const string& str,
                      const string& delimiters, vector<string> &tokens);
                      
#endif
