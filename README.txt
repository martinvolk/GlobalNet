COMPILING
You will need openssl installed with the required libraries (libssl 
and libcrypt). 

apt-get install openssl

(you may need a few other things to compile it that I may not know of, 
but the error messages from the compiler will probably tell you enough 
information on which files are missing so that you can install them). 
Contact me at redbluewebsites@gmail.com if you come across files that 
are missing so I can update these instructions.. 

Then you may need to compile UDT library. If the .a file that comes in 
the repository does not work, go to the udt source directory and do 
"make" there. Then copy the .a file to "lib". 

Then do "make". 

The resulting program is called gclient. 

CERTIFFICATES

You will need to create client.crt/client.key and 
server.crt/server.key. These are private and public keys for the 
client and the server (ie connecting sockets and listening sockets). 

You can create these files using the command line in makecerts.sh file 
that you have in the main directory. 

USAGE

Check out the tests directory for example usage. You can also look at the client program supplied in gclient.cpp. 

LICENSE
Standard GPL v3
