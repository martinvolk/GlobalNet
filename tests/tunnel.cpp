#include "vsocket.h"
#include <iostream>

using namespace std;

int main(int argc, char *argv[]){
	VSL::init();
	
	VSL::SOCKINFO info;
	VSL::VSOCKET socket = VSL::socket(); 
	list<URL> path; 
	
	path.push_back(URL("vsl://localhost:9000"));
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
			cerr<<"Response timed out!"<<endl;
			cout<<"Response: "<<response<<endl;
			return 0;
		}
	}
	cout<<"Response: "<<response<<endl;
	VSL::shutdown();
	return 0;
}
