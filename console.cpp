#include "gclient.h"

/***
CONSOLE SERVICE

Thie service runs on a destined port and listens for commands from user. 

use "nc localhost 2000" to connect and use the console. 
***/

#define SEND_SOCK(sock, msg) { stringstream ss; ss<<msg<<endl; (sock)->send(sock, ss.str().c_str(), ss.str().length());}

string con_state_to_string(ConnectionState state){
	switch(state){
		case CON_STATE_UNINITIALIZED:
			return "CON_STATE_UNINITIALIZED";
		case CON_STATE_CONNECTING:
			return "CON_STATE_CONNECTING";
		case CON_STATE_LISTENING:
			return "CON_STATE_LISTENING";
		case CON_STATE_SSL_HANDSHAKE:
			return "CON_STATE_SSL_HANDSHAKE";
		case CON_STATE_RELAY_PENDING:
			return "CON_STATE_RELAY_PENDING";
		case CON_STATE_ESTABLISHED:
			return "CON_STATE_ESTABLISHED";
		case CON_STATE_CLOSE_PENDING:
			return "CON_STATE_CLOSE_PENDING";
		case CON_STATE_DISCONNECTED:
			return "CON_STATE_DISCONNECTED";
	}
	return "";
}


static int _console_listen(Service &self, const char *host, uint16_t port){
	LOG("[console] starting console service on port "<<port);
	
	Connection *con = NET_createConnection(*self.net, "tcp", false);
	con->listen(*con, host, port);
	self.socket = con;
	
	return 1;
}

static void _console_run(Service &self){
	Connection *client; 
	
	if((client = SRV_accept(self))){
		LOG("new client connected to the console!");
		
		string prompt = "gnet# ";
		client->send(*client, &prompt[0], prompt.length());
	}
	
	for(uint c=0;c<ARRSIZE(self.clients);c++){
		string cmd;
		char str[1024];
		int rs;
		
		Connection *con = self.clients[c];
		if(!con) continue;
		
		if((rs = con->recv(*con, str, 1024))>0){
			str[rs] =0 ;
			cout<<str<<endl;
			
			cmd = str;
		}
		
		if(cmd.length()){
			LOG("[console] processing PacketHeader " << cmd);
			
			if(cmd.compare("listpeers")){
				LOG("test");
				/*
				for(vector<Connection*>::iterator x = self.net->peers.begin(); x != self.net->peers.end(); x++){
					SEND_SOCK(*c, "connection: " << (*x)->host << ":"<<(*x)->port<<" state: "<<con_state_to_string((*x)->state));
				}
				for(vector<Link*>::iterator l = self.net->links.begin(); l != self.net->links.end(); l++){
					SEND_SOCK(*c, "link: ");
					for(vector<Connection*>::iterator x = (*l)->nodes.begin(); x != (*l)->nodes.end(); x++){
						SEND_SOCK(*c, "    connection: " << (*x)->host << ":"<<(*x)->port<<" state: "<<con_state_to_string((*x)->state));
					}
				}*/
				
			}
			else if(cmd == "test"){
				// send an introduction packet
				cout << "Attempting to send test packets.."<<endl;
				Packet pack;
				/*
				for(vector<Connection*>::iterator c = self.net->peers.begin(); c != self.net->peers.end(); c++){
					cout << "Sending test packet.."<<endl;
					string str = "Hello World";
					pack.cmd.code = CMD_TEST;
					pack.cmd.size = str.length();
					//pack.data.resize(sizeof(Command)+pack.cmd.size);
					memcpy(&pack.data[0], str.c_str(), str.length());
					//(*c)->send((*c), pack.c_ptr(), pack.size());
					//CON_sendPacket(*c, pack);
					//CON_sendPacket(conn, pack);
					//CON_sendPacket(conn, pack);
				}
				*/
				/// establish a rendezvous connection to a hidden service (started with -s)
				// this function starts the connection process. Once completed, the service state is set to SRV_STATE_ACTIVE
				// if the operation does not complete in due time, the state will be set to SRV_STATE_DISCONNECTED
				
				
				/// this code should accomplish the same thing as the code below
				/*
				Link *link = NET_createLink(&app->net, "localhost:9000");
				string str = "Hello Server!";
				vector<char> data(str.begin(), str.end());
				LNK_connect(link, "localhost", 3232, REL_PROTO_TCP);
				LNK_sendData(link, data);
				app->net.links.push_back(link);*/
				/*
				Connection *con = new Connection();
				CON_init(con, REL_PROTO_INTERNAL_CLIENT);
				CON_connect(con, "localhost", 9000);
				CON_sendPacket(con, pack);
				app->net.peers.push_back(con);
				Connection *bob = new Connection();
				CON_init(bob, REL_PROTO_INTERNAL_CLIENT);
				CON_bridge(bob, con);
				CON_connect(bob, "localhost", 9001);
				app->net.peers.push_back(bob);
				Connection *alice = new Connection();
				CON_init(alice, REL_PROTO_INTERNAL_CLIENT);
				CON_bridge(alice, bob);
				CON_connect(alice, "localhost", 9000);
				app->net.peers.push_back(alice);
				
				cout << "Sending test packet to bob.."<<endl;
				pack.cmd.code = CMD_DATA;
				pack.cmd.size = str.length();
				pack.data.resize(sizeof(Command)+pack.cmd.size);
				memcpy(&pack.data[0], str.c_str(), str.length());
				CON_sendPacket(alice, pack);*/
				/*
				LOG("testing to create a link");
				Link *link = NET_createLink(&app->net, "5014d1b320016c9557ebf1b44a2d301f90023e12");
				LINKADDRESS addr;
				addr.fromString("5014d1b320016c9557ebf1b44a2d301f90023e11");
				if(!NET_connectLink(&app->net, link, addr)){
					cout << "Could not connect link "<<link->address.hex()<<" to "<<addr.hex()<<endl;
				}
				cout<< "attempting to send data!"<<endl;
				const char *str = string("Hello World!").c_str();
				LNK_sendData(link, vector<char>(str, str + strlen(str)));
				*/
			}
			// send the prompt
			string prompt = "gnet# ";
			con->send(*con, &prompt[0], prompt.length());
		}
	}
}


void SRV_initCONSOLE(Service &self){
	self.initialized = true;
	self.listen = _console_listen;
	self.run = _console_run;
}
