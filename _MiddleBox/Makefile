CC     = g++
CFLAGS = -lpcap -I /home/fanquan/Desktop/boost_1_58_0 -lpthread -lssl -lcrypto
Target = _Middlebox
Obj    = ip4hdr.o tcphdr.o main.o flowkey.o flowmgr.o flowinfo.o ipaddr.o applayerhandler.o tcphandler.o tlshandler.o tls.o ip6hdr.o udphdr.o esphandler.o

$(Target): $(Obj)
	$(CC) -o $(Target) $(Obj) $(CFLAGS)

#ip4hdr.o: ip4hdr.h ip4hdr.cpp
#	$(CC) -c -o ip4hdr.o ip4hdr.cpp $(CFLAGS)

#tcphdr.o: tcphdr.h tcphdr.cpp
#	$(CC) -c -o tcphdr.o tcphdr.cpp $(CFLAGS)

#flowkey.o: flowkey.h flowkey.cpp ipaddr.h
#	$(CC) -c -o flowkey.o flowkey.cpp $(CFLAGS)

#flowmgr.o: flowmgr.h flowmgr.cpp flowkey.h flowinfo.h
#	$(CC) -c -o flowmgr.o flowmgr.cpp $(CFLAGS)

#main.o: ip4hdr.h tcphdr.h main.cpp
#	$(CC) -c -o main.o main.cpp $(CFLAGS)
%.o: %.cpp 
	$(CC) -c -o $@ $<  $(CFLAGS)

.PHONY: clean
clean:
	-rm -f $(Target) *.o
