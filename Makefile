CC     = g++
CFLAGS = -lpcap -I /home/fanquan/Desktop/boost_1_58_0 -lpthread -lssl -lcrypto -lnetfilter_queue -lglib-2.0 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/pbc -I/usr/local/include/pbc -lbswabe -Wl,-rpath /usr/local/lib -lpbc -lgmp
Target = PlainBox
Obj    = ip4hdr.o tcphdr.o main.o flowkey.o flowmgr.o flowinfo.o ipaddr.o applayerhandler.o tcphandler.o tlshandler.o tls.o ip6hdr.o udphdr.o esphandler.o sshhandler.o nfqueue.o abe.o

$(Target): $(Obj) abe_common.o abe_policy.o
	$(CC) -o $(Target) $(Obj) abe_common.o abe_policy.o $(CFLAGS)

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
	
abe_common.o: abe/common.h abe/common.c
	$(CC) -c -o abe_common.o abe/common.c  $(CFLAGS) 

abe_policy.o: abe/policy_lang.h abe/policy_lang.c
	$(CC) -c -o abe_policy.o abe/policy_lang.c  $(CFLAGS) -fpermissive

.PHONY: clean
clean:
	rm -f $(Target) *.o
