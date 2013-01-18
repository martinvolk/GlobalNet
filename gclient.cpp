/*********************************************
GClient - GlobalNet P2P client
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/


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

VSL::VSOCKET SRV_accept(Service &self){
	VSL::VSOCKET con = 0;
	if((con = VSL::accept(self.socket))>0){
		for(uint c=0;c<ARRSIZE(self.clients);c++){
			if(c == ARRSIZE(self.clients)-1){
				ERROR("No more free service sockets available!");
				return 0;
			}
			if(self.clients[c] == 0){
				self.clients[c] = con;
				return con;
			}
		}
	}
	return con;
}

Service socks;
Service console;

void signal_handler(int sig){
	LOG("SHUTTING DOWN!");
	VSL::shutdown();
	exit(1);
}


int check_arg(const option::Option& option, bool msg){
	return option::ARG_OK;
}

int main(int argc, char* argv[])
{
	enum  optionIndex { UNKNOWN, HELP, CONNECT, SERVICE, CONSOLE_PORT, SOCKS_PORT };
	const option::Descriptor usage[] =
	{
		{UNKNOWN, 0,"" , ""    ,option::Arg::None, "USAGE: gclient -c [client:port,client2:port2] [--help]\n\n"
																							 "Options:" },
		{HELP,    0,"" , "help",option::Arg::None, "  --help  \tPrint usage and exit." },
		{CONNECT, 0,"c", "connect", (option::CheckArg)check_arg, "  --connect, -c  \tConnect to other peer [host:port]."},
		{SERVICE, 0,"s", "service", (option::CheckArg)check_arg, "  --service, -s  \tStart a default hidden service."},
		{CONSOLE_PORT, 0,"", "console-port", (option::CheckArg)check_arg, "  --console-port  \tStart a debug console on port."},
		{SOCKS_PORT, 0,"", "socks-port", (option::CheckArg)check_arg, "  --socks-port  \tSpecify socks server listen port (default 8000)."},
		{UNKNOWN, 0,"" ,  ""   ,option::Arg::None, "\nExamples:\n"
																							 "  example --unknown -- --this_is_no_option\n"
																							 "  example -unk --plus -ppp file1 file2\n" },
		{0,0,0,0,0,0}
	};
	
	struct sigaction sigIntHandler;

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
			VSL::add_peer((*i).c_str());
		}
	}
	
	int port = 8000;
	if(options[SOCKS_PORT].count()){
		port = atoi(options[SOCKS_PORT].first()->arg);
	}
	// start the socks service
	SRV_initSOCKS(socks);
	socks.listen(socks, "localhost", port);
	
	SRV_initCONSOLE(console);
	// start the console service
	if(options[CONSOLE_PORT].count() > 0){
		console.listen(console, "localhost", atoi(options[CONSOLE_PORT].first()->arg));
	}
	
	unsigned long usec = 0;
	while(true){
		if((usec % 10000) == 0)
			cout<<".";
			fflush(stdout);
		usec++;
		// run main loop 
		socks.run(socks);
		console.run(console);
		VSL::run();
		usleep(100); // about 100fps
	}
	
	VSL::shutdown();
	
	return 1;
}
