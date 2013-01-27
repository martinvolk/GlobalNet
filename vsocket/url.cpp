#include "local.h"
#include <string>
#include <algorithm>
#include <cctype>
#include <functional>

using namespace std;

URL::URL(const string &url):
	protocol_(""),
	host_("0.0.0.0"),
	path_(""),
	query_(""),
	port_(0)
	{
	parse(url);
}
URL::URL(const URL &other):
	protocol_(other.protocol_),
	host_(other.host_),
	path_(other.path_),
	query_(other.query_),
	port_(other.port_),
	url_(other.url_)
	{
}

URL::URL(const string &proto, const string &host, uint16_t port, const string &path, const string &query):
	protocol_(proto),
	host_(host),
	path_(path),
	query_(query),
	port_(port),
	url_(protocol_+"://"+host_+":"+VSL::to_string(port_)+path_+((query_.length())?("?"+query_):"")){}
	
void URL::parse(const string& url_s)
{
    const string prot_end("://");
    url_ = "";
    
    string::const_iterator prot_i = search(url_s.begin(), url_s.end(),
                                           prot_end.begin(), prot_end.end());
    protocol_.reserve(distance(url_s.begin(), prot_i));
    transform(url_s.begin(), prot_i,
              back_inserter(protocol_),
              ptr_fun<int,int>(tolower)); // protocol is icase
    if( prot_i == url_s.end() )
        return;
    advance(prot_i, prot_end.length());
    
    string::const_iterator port_i = find(prot_i, url_s.end(), ':');
    string::const_iterator path_i = find(prot_i, url_s.end(), '/');
    if(port_i != url_s.end()){
			string::const_iterator tmp = port_i;
			advance(port_i, 1);
			string port; 
			port.assign(port_i, path_i);
			port_ = atoi(port.c_str());
			port_i = tmp;
		}
		else{
			port_i = path_i;
		}
    
    host_ = "";
    host_.reserve(distance(prot_i, port_i));
    transform(prot_i, port_i,
              back_inserter(host_),
              ptr_fun<int,int>(tolower)); // host is icase
              
    
    string::const_iterator query_i = find(path_i, url_s.end(), '?');
    path_.assign(path_i, query_i);
    if( query_i != url_s.end() )
        ++query_i;
    query_.assign(query_i, url_s.end());
    
		url_ = protocol_+"://"+host_+":"+VSL::to_string(port_)+path_+((query_.length())?("?"+query_):"");
}
