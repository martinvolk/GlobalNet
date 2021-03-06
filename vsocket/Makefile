C++ = g++
LD = ar
ifndef os
   os = LINUX
endif

ifndef arch
   arch = IA32
endif

CCFLAGS = -Wall -std=gnu++0x -D$(os) -I../udt/ -finline-functions -fstack-check -fstack-protector-all -O0 -g3 -ggdb3

ifeq ($(arch), IA32)
   CCFLAGS += -DIA32 #-mcpu=pentiumpro -march=pentiumpro -mmmx -msse
endif

ifeq ($(arch), POWERPC)
   CCFLAGS += -mcpu=powerpc
endif

ifeq ($(arch), IA64)
   CCFLAGS += -DIA64
endif

ifeq ($(arch), SPARC)
   CCFLAGS += -DSPARC
endif

LDFLAGS = -L../lib/ -lcrypto -lssl -ludt -lstdc++ -lpthread -lm

ifeq ($(os), UNIX)
   LDFLAGS += -lssl -lcrypto -lsocket
endif

ifeq ($(os), SUNOS)
   LDFLAGS += -lrt -lsocket
endif

DIR = $(shell pwd)
LIB = libvsocket.a
OBJECTS = bridge.o buffer.o if.o db.o node.o socks.o mem.o vsl.o ssl.o tcp.o udt.o net.o vsocket.o adapter.o url.o channel.o

all: $(LIB)

%.h.gch: %.h *.h
	$(C++) $(CCFLAGS) $< -g -c

%.o: %.cpp *.h
	$(C++) $(CCFLAGS) $< -g -c 

$(LIB): local.h.gch $(OBJECTS)
	ar rc $@ $^ 
	
clean:
	rm -f *.o $(LIB)

install:
	export PATH=$(DIR):$$PATH
