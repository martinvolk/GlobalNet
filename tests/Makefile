C++ = g++

ifndef os
   os = LINUX
endif

ifndef arch
   arch = IA32
endif

CCFLAGS = -Wall -D$(os) -I../udt/ -I../vsocket -finline-functions -fstack-check -fstack-protector-all -O0 -g3 -ggdb3

ifeq ($(arch), IA32)
   CCFLAGS += -DIA32 #-mcpu=pentiumpro -march=pentiumpro -mmmx -msse
endif

ifeq ($(arch), POWERPC)
   CCFLAGS += -mcpu=powerpc
endif

ifeq ($(arch), IA64)
   CCFLAGS += -DIA64
endif

LDFLAGS = -L../udt/ -L../vsocket -lvsocket -lcrypto -lssl -ludt -lstdc++ -lpthread -lm

ifeq ($(os), UNIX)
   LDFLAGS += -lssl -lcrypto -lsocket
endif

DIR = $(shell pwd)

APP = tunnel listen rz

all: $(APP) ../vsocket/libvsocket.a
	make -C ../vsocket
	make $(APP)
	
%.o: %.cpp
	$(C++) $(CCFLAGS) $< -c

tunnel: tunnel.o ../vsocket/libvsocket.a
	$(C++) $^ -o $@ $(LDFLAGS)
listen: listen.o ../vsocket/libvsocket.a
	$(C++) $^ -o $@ $(LDFLAGS)
rz: rendezvous.o  ../vsocket/libvsocket.a
	$(C++) $^ -o $@ $(LDFLAGS)
	
../vsocket/libvsocket.a: 
	make -C vsocket
	
clean:
	rm -f *.o $(APP)

install:
	export PATH=$(DIR):$$PATH
