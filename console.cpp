/*********************************************
GClient - GlobalNet P2P client
Martin K. Schröder (c) 2012-2013

Free software. Part of the GlobalNet project. 
**********************************************/

#include "gclient.h"

/***
CONSOLE SERVICE

Thie service runs on a destined port and listens for commands from user. 

use "nc localhost 2000" to connect and use the console. 
***/

#define SEND_SOCK(sock, msg) { stringstream ss; ss<<msg<<endl; (sock)->send(*sock, ss.str().c_str(), ss.str().length());}


ConsoleService::~ConsoleService(){
	for(uint c=0;c<this->clients.size();c++)
		VSL::close(clients[c]);
	if(this->socket) 
		VSL::close(this->socket);
}

int ConsoleService::listen(const URL &url){
	LOG(1,"[console] starting console service on port "<<url.port());
	
	VSL::VSOCKET con = VSL::socket();
	VSL::listen(con, url);
	this->socket = con;
	
	return 1;
}

void ConsoleService::run(){
	VSL::VSOCKET client; 
	
	if((client = VSL::accept(this->socket))){
		LOG(1,"new client connected to the console!");
		clients.push_back(client);
		
		string prompt = "gnet# ";
		VSL::send(client, &prompt[0], prompt.length());
	}
	
	for(uint c=0;c<this->clients.size();c++){
		string cmd;
		char str[1024];
		int rs;
		
		VSL::VSOCKET con = this->clients[c];
		if(!con) continue;
		 
		if((rs = VSL::recv(con, str, 1024))>0){
			str[rs] =0 ;
			cout<<str<<endl;
			
			cmd = str;
		}
		
		if(cmd.length()){
			LOG(1,"[console] processing command " << cmd);
			
			if(cmd.compare("stats")){
				VSL::print_stats(this->clients[c]);
			}
			else if(cmd.compare("listpeers")){
				LOG(1,"test");
				
				
			}
			else if(cmd == "test"){
				
			}
			// send the prompt
			string prompt = "gnet# ";
			VSL::send(con, &prompt[0], prompt.length());
		}
	}
}

