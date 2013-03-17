#include "vsocket.h"
#include <iostream>

using namespace std;

int main(int argc, char *argv[]){
	VSL::init();
	
	VSL::SOCKINFO info;
	VSL::VSOCKET socket = VSL::socket(); 
	list<URL> path; 
	
	path.push_back(URL("vsl://localhost:9000"));
	path.push_back(URL("tcp://localhost:8181"));
	
	VSL::listen(socket, path);
	time_t t = time(0);
	while(true){
		VSL::getsockinfo(socket, &info);
		if(info.state == VSL::VSOCKET_LISTENING){
			cout<<"Now listening on localhost, port 8181."<<endl;
			cout<<" -> try connecting to it with netcat."<<endl;
			break;
		}
		
		if(time(0) - t > 10){
			cerr<<"ERROR LISTENING.. listen timed out!"<<endl;
			return 0;
		}
	}
	
	while(true){
		
		VSL::VSOCKET client = VSL::accept(socket);
		if(client){
			string str = "Type something..\n";
			VSL::send(client, str.c_str(), str.length()+1);
			while(true){
				char tmp[4096];
				VSL::SOCKINFO info;
				
				int rc = VSL::recv(client, tmp, sizeof(tmp));
				if(rc > 0){
					VSL::send(client, tmp, rc);
				}
				VSL::getsockinfo(client, &info);
				if(info.state == VSL::VSOCKET_DISCONNECTED){
					cout<<"listen: REMOTE CLIENT DISCONNECTED! ...................................................."<<endl;
					break;
				}
				usleep(100000);
			}
		}
		usleep(1000);
	}
	VSL::shutdown();
	return 0;
}
