C++ = g++

ifndef os
   os = LINUX
endif

ifndef arch
   arch = IA32
endif

CCFLAGS = -Wall -D$(os) -I./udt/ -finline-functions -fstack-check -fstack-protector-all -O0 -g3 -ggdb3

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

LDFLAGS = -L./udt/ -L./vsocket -lvsocket -lcrypto -lssl -ludt -lstdc++ -lpthread -lm

ifeq ($(os), UNIX)
   LDFLAGS += -lssl -lcrypto -lsocket
endif

ifeq ($(os), SUNOS)
   LDFLAGS += -lrt -lsocket
endif

DIR = $(shell pwd)

APP = gclient
	
all: vsocket/libvsocket.a
	make -C udt
	make -C vsocket
	make -C tests
	rm -f gclient
	make -C . $(APP)

vsocket/libvsocket.a: 
	make -C vsocket
	
%.o: %.cpp *.h
	$(C++) $(CCFLAGS) $< -g -c

$(APP): gclient.o socks.o console.o 
	$(C++) $^ -g -o $@ $(LDFLAGS)
	
clean:
	make -C vsocket clean
	rm -f *.o $(APP)

install:
	export PATH=$(DIR):$$PATH
