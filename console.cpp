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

int ConsoleService::listen(const char *host, uint16_t port){
	LOG("[console] starting console service on port "<<port);
	
	VSL::VSOCKET con = VSL::socket(VSL::SOCKET_TCP);
	stringstream ss;
	ss<<host<<":"<<port;
	VSL::listen(con, ss.str().c_str());
	this->socket = con;
	
	return 1;
}

void ConsoleService::run(){
	VSL::VSOCKET client; 
	
	if((client = VSL::accept(this->socket))){
		LOG("new client connected to the console!");
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
			LOG("[console] processing command " << cmd);
			
			if(cmd.compare("stats")){
				VSL::print_stats(this->clients[c]);
				/*
				uint nc = 0, nl = 0, np = 0;
				for(uint j = 0;j<ARRSIZE(this->net->sockets);j++){
					Connection *sock = &this->net->sockets[j];
					if(sock->initialized){
						nc++;
						SEND_SOCK(this->clients[c], "socket: type: " << sock->type << ": " << sock->host << ":"<<sock->port<<" state: "<<con_state_to_string(sock->state));
					}
				}
				for(uint j = 0;j<ARRSIZE(this->net->links);j++){
					Link *link = &this->net->links[j];
					if(link->initialized){
						nl++;
						//SEND_SOCK(*c, "socket: " << (*x)->host << ":"<<(*x)->port<<" state: "<<con_state_to_string((*x)->state));
					}
				}
				for(uint j = 0;j<ARRSIZE(this->net->peers);j++){
					Peer *peer = &this->net->peers[j];
					if(peer && peer->initialized){
						np++;
						SEND_SOCK(this->clients[c], "peer: " << peer->socket->host << ":"<<peer->socket->port<<" state: "<<con_state_to_string(peer->socket->state));
					}
				}
				SEND_SOCK(con, "Connections: "<<nc<<"/"<<ARRSIZE(this->net->sockets)<<", Links: "<<nl<<"/"<<ARRSIZE(this->net->links)<<
						"Peers: "<<np<<"/"<<ARRSIZE(this->net->peers));*/
				/*		
				for(vector<Connection*>::iterator x = this->net->peers.begin(); x != this->net->peers.end(); x++){
					SEND_SOCK(*c, "connection: " << (*x)->host << ":"<<(*x)->port<<" state: "<<con_state_to_string((*x)->state));
				}
				for(vector<Link*>::iterator l = this->net->links.begin(); l != this->net->links.end(); l++){
					SEND_SOCK(*c, "link: ");
					for(vector<Connection*>::iterator x = (*l)->nodes.begin(); x != (*l)->nodes.end(); x++){
						SEND_SOCK(*c, "    connection: " << (*x)->host << ":"<<(*x)->port<<" state: "<<con_state_to_string((*x)->state));
					}
				}*/
			}
			else if(cmd.compare("listpeers")){
				LOG("test");
				/*
				for(vector<Connection*>::iterator x = this->net->peers.begin(); x != this->net->peers.end(); x++){
					SEND_SOCK(*c, "connection: " << (*x)->host << ":"<<(*x)->port<<" state: "<<con_state_to_string((*x)->state));
				}
				for(vector<Link*>::iterator l = this->net->links.begin(); l != this->net->links.end(); l++){
					SEND_SOCK(*c, "link: ");
					for(vector<Connection*>::iterator x = (*l)->nodes.begin(); x != (*l)->nodes.end(); x++){
						SEND_SOCK(*c, "    connection: " << (*x)->host << ":"<<(*x)->port<<" state: "<<con_state_to_string((*x)->state));
					}
				}*/
				
			}
			else if(cmd == "test"){
				// send an introduction packet
				cout << "Attempting to send test packets.."<<endl;
				//Packet pack;
				/*
				for(vector<Connection*>::iterator c = this->net->peers.begin(); c != this->net->peers.end(); c++){
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
				SHA1Hash addr;
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
			VSL::send(con, &prompt[0], prompt.length());
		}
	}
}

