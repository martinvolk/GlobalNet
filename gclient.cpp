/*********************************************
GClient - GlobalNet P2P client
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

/* 

EXAMPLES FOR TUNNELLING: 
# from server establish connection to middleman and listen on port 1414
./gclient --socks-port 8080 --listen "tcp://localhost:8080|vsl://middleman_node:9000|tcp://localhost:1414"
# from client computer set up so that all connections to port 8002 get forwarded to 
# middleman through a chain of other nodes. 
# this command will alias local port 8002 so that all connections made to it go to the middleman port 1414.
./gclient --alias "tcp://localhost:8002|vsl://third_party:9000|tcp://middleman_node:1414"

# now since local port 8002 is connected to socks proxy port on the hidden server, 
# you can set your localhost:8002 as socks5 proxy in web browser and browse the 
# web as viewed from the remote hidden server. (of course if it is connected to the internet
# we would easily be able to figure out it's identity - but this is just an example of how to run 
# hidden services). 
*/
#include "gclient.h"

using namespace std;

pthread_mutex_t gmutex = PTHREAD_MUTEX_INITIALIZER;
#ifndef WIN32
void* recvdata(void*);
#else
DWORD WINAPI recvdata(LPVOID);
#endif


//#define x(msg) 
//#define NO_SSL


///*******************************************
/// SERVICE
///*******************************************

void SRV_shutdown(Service &self){
	
}

/*
VSL::VSOCKET Service::accept(){
	VSL::VSOCKET con = 0;
	if((con = VSL::accept(this->socket))>0){
		for(uint c=0;c<ARRSIZE(this->clients);c++){
			if(c == ARRSIZE(this->clients)-1){
				ERROR("No more free service sockets available!");
				return 0;
			}
			if(this->clients[c] == 0){
				this->clients[c] = con;
				return con;
			}
		}
	}
	return con;
}
*/
Service *socks;
Service *console;
SecretService *secret;

void cleanup(){
	LOG(1, "EXITING!");
	VSL::shutdown();
}

static bool shutting_down = false;
void signal_handler(int sig){
	if(shutting_down) {
		LOG(1,"SHUTDOWN ALREADY IN PROGRESS!");
		return;
	}
	
	LOG(1,"SHUTTING DOWN!");
	is_running = false;
}


int check_arg(const option::Option& option, bool msg){
	return option::ARG_OK;
}

int main(int argc, char* argv[])
{
	enum  optionIndex { UNKNOWN, HELP, CONNECT, SERVICE, ALIAS, CONSOLE_PORT, SOCKS_PORT };
	const option::Descriptor usage[] =
	{
		{UNKNOWN, 0,"" , ""    ,option::Arg::None, "USAGE: gclient -c [client:port,client2:port2] [--help]\n\n"
																							 "Options:" },
		{HELP,    0,"" , "help",option::Arg::None, "  --help  \tPrint usage and exit." },
		{CONNECT, 0,"c", "connect", (option::CheckArg)check_arg, "  --connect, -c  \tConnect to other peer [host:port]."},
		{SERVICE, 0,"l", "listen", (option::CheckArg)check_arg, "  --listen, -s  \tHidden service forwarding. [secrethost:port]<[linkhost1>linkhost2..]>[remote_listen_addr:port]"},
		{ALIAS, 	0,"a", "alias", (option::CheckArg)check_arg, "--alias, -a \tAlias a local port to a remote port."},
		{CONSOLE_PORT, 0,"", "console-port", (option::CheckArg)check_arg, "  --console-port  \tStart a debug console on port."},
		{SOCKS_PORT, 0,"", "socks-port", (option::CheckArg)check_arg, "  --socks-port  \tSpecify socks server listen port (default 8000)."},
		{UNKNOWN, 0,"" ,  ""   ,option::Arg::None, "\nExamples:\n"
																							 "  example --unknown -- --this_is_no_option\n"
																							 "  example -unk --plus -ppp file1 file2\n" },
		{0,0,0,0,0,0}
	};
	
	struct sigaction sigIntHandler;
	
	atexit(cleanup);
	
	sigIntHandler.sa_handler = signal_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
	
  argc-=(argc>0); argv+=(argc>0); // skip program name argv[0] if present
	option::Stats  stats(usage, argc, argv);
	option::Option options[stats.options_max], buffer[stats.buffer_max];
	option::Parser parse(usage, argc, argv, options, buffer);

	if (parse.error()){
	 option::printUsage(std::cout, usage);
	 return 0;
	}
	
	if (options[HELP]) {
	 option::printUsage(std::cout, usage);
	 return 0;
	}
	
	//memset(&app, 0, sizeof(app));
	
	VSL::init();
	//VSL::set_option("client_crt", "client.crt");
	//VSL::set_option("client_key", "client.key");
	//VSL::set_option("server_crt", "server.crt");
	//VSL::set_option("server_key", "server.key");
	//VSL::set_option("anonymity_level", "1");

	// find all peers
	if(options[CONNECT].count() > 0){
		vector<string> peers;
		tokenize(string(options[CONNECT].first()->arg), string(","), peers);
		for(vector<string>::iterator i = peers.begin(); i!=peers.end();i++){
			// this will extend the network with actual physical peers identified by an IP address. 
			VSL::VSOCKET sock = VSL::socket();
			VSL::connect(sock, URL("vsl://"+(*i)));
		}
	}
	
	int port = 8000;
	if(options[SOCKS_PORT].count()){
		port = atoi(options[SOCKS_PORT].first()->arg);
	}
	// start the socks service
	Service *socks = new SocksService();
	Service *console = new ConsoleService(); 
	SecretService *secret = new SecretService();
	
	if(socks->listen(URL("socks", "127.0.0.1", port)) == -1){
		delete socks;
		delete console; 
		return 0;
	}
	
	// start the console service
	if(options[CONSOLE_PORT].count() > 0){
		console->listen(URL("tcp", "127.0.0.1", atoi(options[CONSOLE_PORT].first()->arg)));
	} else {
		console->listen(URL("tcp", "127.0.0.1", 2000));
	}
	
	// alias local ports to remote counterparts
	if(options[ALIAS].count() > 0){
		string path = options[ALIAS].first()->arg;
		vector<string> parts; 
		vector<string> splits;
		tokenize(path, "|", parts);
		tokenize(parts[1], ">", splits);
		list<URL> list; 
		for(vector<string>::iterator i = splits.begin(); 
				i != splits.end(); i++){
			list.push_back(URL(*i));
		}
		secret->addConnectionChain(URL(parts[0]), list, URL(parts[2]));
	}
	
	// start hidden service
	if(options[SERVICE].count() > 0){
		string path = options[SERVICE].first()->arg;
		vector<string> parts; 
		vector<string> splits;
		tokenize(path, "|", parts);
		tokenize(parts[1], ">", splits);
		list<URL> list; 
		for(vector<string>::iterator i = splits.begin(); 
				i != splits.end(); i++){
			list.push_back(URL(*i));
		}
		secret->addListeningChain(URL(parts[0]), list, URL(parts[2]));
	}
	
	unsigned long usec = 0;
	while(!shutting_down){
		if(LOGLEVEL > 1){
			if((usec % 100) == 0)
				cout<<"M";
				fflush(stdout);
			usec++;
		}
		// run main loop 
		socks->run();
		console->run();
		secret->run();
		usleep(1000); // microseconds
	}
	delete socks;
	delete console; 
	delete secret;
	
	shutting_down = true;
	
	return 1;
}
