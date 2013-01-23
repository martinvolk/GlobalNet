

/*
struct ifreq {
    char ifr_name[IFNAMSIZ];         // Interface name
    union {
        struct sockaddr ifr_addr;    // Interface address (we use this)
        struct sockaddr ifr_dstaddr;
        struct sockaddr ifr_broadaddr;
        struct sockaddr ifr_netmask;
        struct sockaddr ifr_hwaddr;
        short ifr_flags;
        int ifr_ifindex;
        int ifr_metric;
        int ifr_mtu;
        struct ifmap ifr_map;
        char ifr_slave[IFNAMSIZ];
        char ifr_newname[IFNAMSIZ];
        char *ifr_data;
    };
};
 
struct ifconf {
    int ifc_len;    // length of ifc_req buffer
    union {
        char *ifc_buf;    // buffer address (we use this)
        struct ifreq *ifc_req;    
    };
};
*/
#include <sys/ioctl.h>
#include <vector>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netdevice.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "local.h"

#define MAXINTERFACES 20
 
using namespace std;



// Print errors and exit
void diep(const char *s)
{
    perror(s);
    exit(1);
}

static uint32_t ip_to_int(const std::string ip) {
    int a, b, c, d;
    uint32_t addr = 0;
 
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;
 
    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
}

bool inet_ip_in_range(const std::string ip, const std::string network, const std::string mask) {
    uint32_t ip_addr = ip_to_int(ip);
    uint32_t network_addr = ip_to_int(network);
    uint32_t mask_addr = ip_to_int(mask);
 
    uint32_t net_lower = (network_addr & mask_addr);
    uint32_t net_upper = (net_lower | (~mask_addr));
 
    if (ip_addr >= net_lower &&
        ip_addr <= net_upper)
        return true;
    return false;
}

string inet_get_host_ip(const string &hostname){
	const hostent* host_info = gethostbyname(hostname.c_str()) ;
	if (host_info) {
		const in_addr* address = (in_addr*)host_info->h_addr_list[0] ;
		string ip = inet_ntoa(*address);
		return ip;
	}
	return "0.0.0.0";
}

/** 
Returns true if the passed ip address belong to a local subnet. 
**/
bool inet_ip_is_local(const string &ip){
	return (inet_ip_in_range(ip, "10.0.0.0", "255.0.0.0") || 
					inet_ip_in_range(ip, "172.16.0.0", "255.240.0.0") ||
					inet_ip_in_range(ip, "192.168.0.0", "255.255.0.0") || 
					inet_ip_in_range(ip, "127.0.0.0", "255.0.0.0"));
}

string inet_get_ip(const string &host){
	struct hostent *he;
	struct in_addr **addr_list;
	
	if ((he = gethostbyname(host.c_str())) == NULL) {  // get the host info
			herror("gethostbyname");
			return "0.0.0.0";
	}
	addr_list = (struct in_addr **)he->h_addr_list;
	if(addr_list[0] != NULL)
		return inet_ntoa(*addr_list[0]);
	return "0.0.0.0";
}

vector< pair<string, string> > inet_get_interfaces()
{
    int sock;
    struct ifconf ifconf;
    struct ifreq ifreq[MAXINTERFACES];
    int interfaces;
    int i;
 
    // Create a socket or return an error.
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        diep("socket");
 
    // Point ifconf's ifc_buf to our array of interface ifreqs.
    ifconf.ifc_buf = (char *) ifreq;
    
    // Set ifconf's ifc_len to the length of our array of interface ifreqs.
    ifconf.ifc_len = sizeof ifreq;
 
    //  Populate ifconf.ifc_buf (ifreq) with a list of interface names and addresses.
    if (ioctl(sock, SIOCGIFCONF, &ifconf) == -1)
        diep("ioctl");
 
    // Divide the length of the interface list by the size of each entry.
    // This gives us the number of interfaces on the system.
    interfaces = ifconf.ifc_len / sizeof(ifreq[0]);
 
    // Print a heading that includes the total # of interfaces.
    printf("IF(%d)tIPn", interfaces);
    
    vector< pair<string, string> > ret; 
    // Loop through the array of interfaces, printing each one's name and IP.
    for (i = 0; i < interfaces; i++) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *address = (struct sockaddr_in *) &ifreq[i].ifr_addr;
 
        // Convert the binary IP address into a readable string.
        if (!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip)))
            diep("inet_ntop");
				
       ret.push_back(pair<string, string>(ifreq[i].ifr_name, ip));
    }
 
    close(sock);
 
    return ret;
}
