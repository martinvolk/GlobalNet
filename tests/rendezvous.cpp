#include "vsocket.h"
#include <iostream>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace std;

int main(int argc, char *argv[]){
	VSL::init();  
	
	VSL::SOCKINFO info1, info2;
	VSL::VSOCKET one = VSL::socket(); 
	VSL::VSOCKET two = VSL::socket();
	int port = rand()%63586+2000;
	
	VSL::bind(one, URL("vsl", "localhost", port));
	VSL::connect(one, URL("vsl", "localhost", port+1));
	
	VSL::bind(two, URL("vsl", "localhost", port+1));
	VSL::connect(two, URL("vsl", "localhost", port));

	time_t t = time(0);
	while(true){
		char tmp[4096];
		int rc; 
		memset(tmp, 0, sizeof(tmp));
		
		VSL::getsockinfo(one, &info1);
		VSL::getsockinfo(two, &info2);
		if(info1.state == VSL::VSOCKET_CONNECTED &&
				info2.state == VSL::VSOCKET_CONNECTED){
			static bool sent = false;
			string str = "Hello World!";
			if(!sent)
				VSL::send(one, str.c_str(), str.length()+1);
			sent = true;
		}
		
		if((rc = VSL::recv(two, tmp, sizeof(tmp)-1))>0){
			cout<<"Response received: "<<string(tmp, tmp+rc)<<endl;
			break;
		}
		
		if(time(0) - t > 10){
			cerr<<"Connection timed out!"<<endl;
			break;
		}
	}
	VSL::shutdown();
	return 0;
}
