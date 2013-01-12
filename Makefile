C++ = g++

ifndef os
   os = LINUX
endif

ifndef arch
   arch = IA32
endif

CCFLAGS = -Wall -D$(os) -I./udt/ -finline-functions -fstack-protector-all -O0 -g3 -ggdb3

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

LDFLAGS = -L./lib/ -lcrypto -lssl -ludt -lstdc++ -lpthread -lm

ifeq ($(os), UNIX)
   LDFLAGS += -lssl -lcrypto -lsocket
endif

ifeq ($(os), SUNOS)
   LDFLAGS += -lrt -lsocket
endif

DIR = $(shell pwd)

APP = gclient

all: $(APP)

%.o: %.cpp *.h
	$(C++) $(CCFLAGS) $< -g -c

gclient: gclient.o socks.o console.o connection.o peer_connection.o ssl_connection.o tcp_connection.o udt_connection.o
	$(C++) $^ -g -o $@ $(LDFLAGS)
clean:
	rm -f *.o $(APP)

install:
	export PATH=$(DIR):$$PATH
