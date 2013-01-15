COMPILING
You will need openssl installed with the required libraries (libssl 
and libcrypt). 

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

-- connect to localhost and start a console and socks proxy. (you may 
want to connect to some other host rather than localhost, but for the 
sake of testing local connections are allowed. What this will mean, is 
that relay connections are established through the localhost peer that 
is connected to localhost - so essentially the software will be 
connected to itself as a peer. 

gclient -c "localhost:9000" --console-port 2000 --socks-port 8000

Now you should be able to use the socks proxy that is running on port 
8000 to make connections through the GlobalNet network. 
