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
	shutting_down = true;
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
/*
VSL::SOCKINFO info;
VSL::VSOCKET socket = VSL::socket(); 
list<URL> path; 
//path.push_back(URL("vsl://localhost:9000"));
path.push_back(URL("vsl://31.192.230.183:9000"));
//path.push_back(URL("vsl://31.192.230.183:9000"));
//path.push_back(URL("vsl://85.224.229.245:9000"));
path.push_back(URL("tcp://whatismyip.com:80"));

VSL::connect(socket, path);

string request = "GET /\n";
string response = "";
VSL::send(socket, request.c_str(), request.length());

time_t t = time(0);
while(true){
  char tmp[4096];
  int rc; 
  memset(tmp, 0, sizeof(tmp));
  
  VSL::getsockinfo(socket, &info);
  if(info.state == VSL::VSOCKET_DISCONNECTED)
    break;
  
  if((rc = VSL::recv(socket, tmp, sizeof(tmp)-1))>0){
    response += tmp;
  }
  
  if(time(0) - t > 10){
    ERROR("Response timed out!");
cout<<"Response: "<<response<<endl;
   return 0;
  }
}
cout<<"Response: "<<response<<endl;
VSL::shutdown();
return 0;
*/
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
		usleep(1000); // microseconds
	}
	delete socks;
	delete console; 
	
	shutting_down = true;
	
	return 1;
}
