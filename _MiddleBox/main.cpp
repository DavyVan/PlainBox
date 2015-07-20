#include<pcap.h>
#include<iostream>
#include<cstdio>
#include <errno.h>
#include<memory.h>
#include"ip4hdr.h"
#include"ip6hdr.h"
#include"tcphdr.h"
#include"udphdr.h"
#include"flowkey.h"
#include"flowmgr.h"
#include"flowinfo.h"
#include"ipaddr.h"
#include "tls.h"
#include"esphandler.h"
#include "nfqueue.h"
#include "abe.h"
#include <signal.h>
using namespace std;

FlowMgr flowMgr = FlowMgr();

int drop;
int doexit = 0;

//Do something when we get a new packet
void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    if (doexit)
    {
        nfqueue_close();
        exit(0);
    }
    drop = 0;
    //get IP and TCP headers, but above all we must look which IP protocol version will use.
    uint8_t ip_version;
    memcpy(&ip_version, packet+14, 1);
    ip_version>>=4;
    if(ip_version == 4)
    {
        //ipv4
        IP4Hdr ip4hdr = IP4Hdr(packet + 14);

        if(ip4hdr.getProtocol() == 6)       //If it's TCP
        {
            TCPHdr tcphdr = TCPHdr(packet + 14 + ip4hdr.getHL());
            //cout<<ip4hdr.getSrcIPstr()<<":"<<tcphdr.getSrcPort()<<" --> "<<ip4hdr.getDestIPstr()<<":"<<tcphdr.getDestPort()<<endl;

            //Check whether the flow exists or not
            IPv4Addr *ip1 = new IPv4Addr(ip4hdr.getSrcIP());
            uint16_t port1 = tcphdr.getSrcPort();
            IPv4Addr *ip2 = new IPv4Addr(ip4hdr.getDestIP());
            uint16_t port2 = tcphdr.getDestPort();
            FlowKey key = FlowKey(ip1, port1, ip2, port2);

            FlowInfoPtr value = flowMgr.findFlow(key);
            /*
            if(value)
            {
                cout<<"ptr is not empty\n";
            }
            else
                cout<<"flow is not exist!\n";
            */

            //cout<<"SYN:"<<tcphdr.isSYN()<<" ACK:"<<tcphdr.isACK()<<" FIN:"<<tcphdr.isFIN()<<" RST:"<<tcphdr.isRST()<<endl;
            //manage flow
            //NOTICE: if the browser keep the tcp alive, then next test will be no tcp connection established
            if(!value && tcphdr.isSYN() && !tcphdr.isACK())     //tcp handshake step 1
            {
                value = flowMgr.addNewFlow(key);
                //cout<<"new flow added  "<<endl;
            }
            else if(value && value->getStatus() == TCP_HANDSHAKING && tcphdr.isSYN() && tcphdr.isACK())     //tcp handshake step 2
            {
                value->statusChange(TCP_WORKING);
                //cout<<"flow changed to tcp_working\n";
            }
            else if(value && value->getStatus() == TCP_WORKING && tcphdr.isFIN())
            {
                value->statusChange(TCP_TERMINATING);
                //cout<<"flow changed to tcp_terminating\n";
            }
            else if(value && value->getStatus() == TCP_TERMINATING && tcphdr.isFIN())
            {
                flowMgr.deleteFlow(key);
                //cout<<"flow deleted normally\n";
                return;
            }
            else if(value && tcphdr.isRST())
            {
                flowMgr.deleteFlow(key);
                //cout<<"flow deleted c'z reseted\n";
            }
            else if(value && (value->getStatus() == TCP_WORKING || value->getStatus() == TCP_TERMINATING))
            {
                //handle tcp payload
                const uint8_t* tcp_payload = packet + 14 + ip4hdr.getHL() + tcphdr.getHL();
                unsigned int tcp_payload_len = ip4hdr.getTotalLen() - ip4hdr.getHL() - tcphdr.getHL();
                //cout<<"TotalLen="<<ip4hdr.getTotalLen() <<endl;
                //cout<<"iphdr length="<<ip4hdr.getHL()<<endl;
                //cout<<"tcphdr length="<<tcphdr.getHL()<<endl;
                //cout<<"tcp_payload_len1="<<tcp_payload_len<<endl;
                if(tcp_payload_len != 0)
                {
                    //cout<<"-------------------------Flow ID: "<<value->ID<<"-----------------------------\n";
                    //cout<<ip4hdr.getSrcIPstr()<<":"<<tcphdr.getSrcPort()<<" --> "<<ip4hdr.getDestIPstr()<<":"<<tcphdr.getDestPort()<<endl;
                    if (tcphdr.header.seq == 0 && tcphdr.header.check == 0)  //extra packet sent by us
                    {
                        cout<<ip4hdr.getSrcIPstr()<<":"<<tcphdr.getSrcPort()<<" --> "<<ip4hdr.getDestIPstr()<<":"<<tcphdr.getDestPort()<<endl;
                        value->handleKeys(tcp_payload, tcp_payload_len);
                        return;
                    }


                    int ret = value->handleTCPPacket(ip1, port1, ip2, port2, tcp_payload, tcp_payload_len, tcphdr.getSeq());
                    if (value->abe.len > 0)
                    {
                        int c2s = 0;
                        /* NOTICE: require client's IP < server's IP */
                        if (equalto(ip1->getAddr_raw(), value->key.getIP1()->getAddr_raw(), 4)) c2s = 1;
                        printf("\nTCP: ret=%d  tcp_payload_len=%d pabe_l=%d\n", ret, tcp_payload_len, value->abe.len);
                        cout<<ip4hdr.getSrcIPstr()<<":"<<tcphdr.getSrcPort()<<" --> "<<ip4hdr.getDestIPstr()<<":"<<tcphdr.getDestPort()<<endl;
                        if (sendTCPWithOption((packet + 14), value->abe, c2s))
                        {
                            drop = 1;
                        }
                        //doexit = 1;
                        value->abe.len = 0;
                        delete []value->abe.f;
                    }
                }

            }
            else
            {
                //cout<<"this pkt is skiped\n";
//                const uint8_t* tcp_payload = packet + 14 + ip4hdr.getHL() + tcphdr.getHL();
//                unsigned int tcp_payload_len = ip4hdr.getTotalLen() - ip4hdr.getHL() - tcphdr.getHL();
//                if(port1 == 500 || port2 == 500)    //For ESP, special case
//                {
//                    printf("TCP::handleKEYS! len=%d\n", tcp_payload_len);
//                    ABEFile abe = abe_decrypt(tcp_payload);
//                    printf("after ABE_DEC: len=%d\n", abe.len);
//                    ESPHandler::handleKeys(abe.f, abe.len);
//                    delete []abe.f;
//                    return;
//                }
                return;//skip this packet
            }
        }
        else if(ip4hdr.getProtocol() == 17)     //If it's UDP
        {
            UDPHdr _udphdr = UDPHdr(packet + 14 + ip4hdr.getHL());

            IPv4Addr *ip1 = new IPv4Addr(ip4hdr.getSrcIP());
            IPv4Addr *ip2 = new IPv4Addr(ip4hdr.getDestIP());
            uint16_t port1 = _udphdr.getSrcPort();
            uint16_t port2 = _udphdr.getDestPort();

            if(port1 == 500 || port2 == 500)        //If it's ISAKMP in port 500
            {
                FlowKey key = FlowKey(ip1, port1, ip2, port2);
                FlowInfoPtr value = flowMgr.findFlow(key);

                if(!value)
                {
                    value = flowMgr.addNewFlow(key);
                    cout<<"new flow added\n";
                }
            }
            else if(port1 == 6666 || port2 == 6666)
            {
                printf("UDP::handleKEYs! len=%d\n", _udphdr.getLength()-8);
                ABEFile abe = abe_decrypt(packet + 14 + ip4hdr.getHL() + 8);
                printf("after ABE_DEC: len=%d\n", abe.len);
                ESPHandler::handleKeys(abe.f, abe.len);
                delete []abe.f;
                return;
            }

        }
        else if(ip4hdr.getProtocol() == 50)     //If it's ESP
        {
            IPv4Addr *ip1 = new IPv4Addr(ip4hdr.getSrcIP());
            IPv4Addr *ip2 = new IPv4Addr(ip4hdr.getDestIP());

            FlowKey key = FlowKey(ip1, 500, ip2, 500);
            int c2s = 0;
            /* NOTICE: require client's IP < server's IP */
            if (equalto(ip1->getAddr_raw(), key.getIP1()->getAddr_raw(), 4)) c2s = 1;

            uint8_t plaint[10000] = {0};
            unsigned int plaintlen;
            if(!ESPHandler::parseAndDecrypt(ip4hdr.getTotalLen() - ip4hdr.getHL(), packet+14+ip4hdr.getHL(), plaint, plaintlen, c2s))
            {
                cout<<"decryption failed!\n";
                return;
            }

            // for(int i = 0; i < plaintlen; i++)
            //     printf("%c", plaint[i]);
            // cout<<endl;

            return;
            //If something over IPsec(ESP)
            uint8_t nextHeader = plaint[plaintlen-1];
            uint8_t padding_len = plaint[plaintlen - 2];
            if(nextHeader == 6)
            {
                cout<<"ESP is protecting TCP\n";
                TCPHdr tcphdr = TCPHdr(plaint);

                uint16_t port1 = tcphdr.getSrcPort();
                uint16_t port2 = tcphdr.getDestPort();

                /* This is a new flow, do not re-use the flow that ISAKMP have used. */
                FlowKey key = FlowKey(ip1, port1, ip2, port2);
                FlowInfoPtr value = flowMgr.findFlow(key);

                // if(value)
                //     cout<<"ptr is not empty\n";
                // else
                //     cout<<"ptr is empty\n";

                //manage flow
                if(!value && tcphdr.isSYN() && !tcphdr.isACK())     //tcp handshake step 1
                {
                    value = flowMgr.addNewFlow(key);
                    cout<<"new flow added  "<<endl;
                }
                else if(value && value->getStatus() == TCP_HANDSHAKING && tcphdr.isSYN() && tcphdr.isACK())     //tcp handshake step 2
                {
                    value->statusChange(TCP_WORKING);
                    cout<<"flow changed to tcp_working\n";
                }
                else if(value && value->getStatus() == TCP_WORKING && tcphdr.isFIN())
                {
                    value->statusChange(TCP_TERMINATING);
                    cout<<"flow changed to tcp_terminating\n";
                }
                else if(value && value->getStatus() == TCP_TERMINATING && tcphdr.isFIN())
                {
                    flowMgr.deleteFlow(key);
                    cout<<"flow deleted normally\n";
                    return;
                }
                else if(value && tcphdr.isRST())
                {
                    flowMgr.deleteFlow(key);
                    cout<<"flow deleted c'z reseted\n";
                }
                else if(value && (value->getStatus() == TCP_WORKING || value->getStatus() == TCP_TERMINATING))
                {
                    //handle tcp payload
                    const uint8_t* tcp_payload = plaint + tcphdr.getHL();
                    unsigned int tcp_payload_len = plaintlen - padding_len - 2 - tcphdr.getHL();
                    cout<<"tcphdr length="<<tcphdr.getHL()<<endl;
                    cout<<"tcp_payload_len="<<tcp_payload_len<<endl;
                    if(tcp_payload_len != 0)
                    {
                        //cout<<"-------------------------Flow ID: "<<value->ID<<"-----------------------------\n";
                        //cout<<*ip1<<":"<<port1<<" --> "<<*ip2<<":"<<port2<<endl;
                        value->handleTCPPacket(ip1, port1, ip2, port2, tcp_payload, tcp_payload_len, tcphdr.getSeq());
                    }

                }
                else
                {
                    //cout<<"this pkt is skiped\n";
                    return;     //skip this packet
                }
            }
        }
    }
    else if(ip_version == 6)
    {
        IP6Hdr ip6hdr = IP6Hdr(packet + 14);

        if(ip6hdr.getNextHeader() == 17)    //If it's UDP
        {
            UDPHdr _udphdr = UDPHdr(packet + 14 + 40);  //NOTICE: we assumpt no options in ipv6 header

            uint8_t t[16];
            ip6hdr.getSrcIP(t);
            IPv6Addr *ip1 = new IPv6Addr(t);
            ip6hdr.getDestIP(t);
            IPv6Addr *ip2 = new IPv6Addr(t);
            uint16_t port1 = _udphdr.getSrcPort();
            uint16_t port2 = _udphdr.getDestPort();

            if(port1 == 500 || port2 == 500)    //If it's ISAKMP in port 500
            {
                //cout<<*ip1<<":"<<port1<<" --> "<<*ip2<<":"<<port2<<endl;

                FlowKey key = FlowKey(ip1, port1, ip2, port2);

                FlowInfoPtr value = flowMgr.findFlow(key);
                /*                if(value)
                                    cout<<"ptr is not empty\n";
                                else
                                    cout<<"ptr is empty\n";
                */
                //manage flow, because it's UDP so nothing to do except adding this flow
                if(!value)
                {
                    value = flowMgr.addNewFlow(key);
                    cout<<"new flow added\n";
                }

                //no need to process ISAKMP packet here, ESP is more important.
            }
        }
        else if(ip6hdr.getNextHeader() == 50)   //If it's ESP
        {
            uint8_t t[16];
            ip6hdr.getSrcIP(t);
            IPv6Addr *ip1 = new IPv6Addr(t);
            ip6hdr.getDestIP(t);
            IPv6Addr *ip2 = new IPv6Addr(t);
            cout<<*ip1<<" --> "<<*ip2<<endl;
            cout<<"--------------------ESP----------------------\n";
            //uint8_t *plaint = new uint8_t[10000];
            uint8_t plaint[10000] = {0};
            unsigned int plaintlen;
            if(!ESPHandler::parseAndDecrypt(ip6hdr.getPayloadLen(), packet+14+40, plaint, plaintlen, 0))     //NOTICE: I assumpt that no v6 options header.
                cout<<"decryption failed!\n";
            //cout<<hex;
            // cout<<"plaint text length: "<<plaintlen<<endl;
            // for(int i = 0; i < plaintlen; i++)
            //     printf("%02x", plaint[i]);
            // cout<<endl;
            // for(int i = 0; i < plaintlen; i++)
            //     printf("%c", plaint[i]);
            // cout<<endl;

            //If something over IPsec(ESP)
            uint8_t nextHeader = plaint[plaintlen-1];
            uint8_t padding_len = plaint[plaintlen - 2];
            if(nextHeader == 58)
                cout<<"ESP is protecting ICMPv6.\n";
            else if(nextHeader == 6)
            {
                cout<<"ESP is protecting TCP\n";
                TCPHdr tcphdr = TCPHdr(plaint);

                uint16_t port1 = tcphdr.getSrcPort();
                uint16_t port2 = tcphdr.getDestPort();

                //cout<<"SYN:"<<tcphdr.isSYN()<<" ACK:"<<tcphdr.isACK()<<" FIN:"<<tcphdr.isFIN()<<" RST:"<<tcphdr.isRST()<<endl;
                /* This is a new flow, do not re-use the flow that ISAKMP have used. */
                FlowKey key = FlowKey(ip1, port1, ip2, port2);
                FlowInfoPtr value = flowMgr.findFlow(key);

                // if(value)
                //     cout<<"ptr is not empty\n";
                // else
                //     cout<<"ptr is empty\n";

                //manage flow
                if(!value && tcphdr.isSYN() && !tcphdr.isACK())     //tcp handshake step 1
                {
                    value = flowMgr.addNewFlow(key);
                    cout<<"new flow added  "<<endl;
                }
                else if(value && value->getStatus() == TCP_HANDSHAKING && tcphdr.isSYN() && tcphdr.isACK())     //tcp handshake step 2
                {
                    value->statusChange(TCP_WORKING);
                    cout<<"flow changed to tcp_working\n";
                }
                else if(value && value->getStatus() == TCP_WORKING && tcphdr.isFIN())
                {
                    value->statusChange(TCP_TERMINATING);
                    cout<<"flow changed to tcp_terminating\n";
                }
                else if(value && value->getStatus() == TCP_TERMINATING && tcphdr.isFIN())
                {
                    flowMgr.deleteFlow(key);
                    cout<<"flow deleted normally\n";
                    return;
                }
                else if(value && tcphdr.isRST())
                {
                    flowMgr.deleteFlow(key);
                    cout<<"flow deleted c'z reseted\n";
                }
                else if(value && (value->getStatus() == TCP_WORKING || value->getStatus() == TCP_TERMINATING))
                {
                    //handle tcp payload
                    const uint8_t* tcp_payload = plaint + tcphdr.getHL();
                    unsigned int tcp_payload_len = plaintlen - padding_len - 2 - tcphdr.getHL();
                    cout<<"tcphdr length="<<tcphdr.getHL()<<endl;
                    cout<<"tcp_payload_len="<<tcp_payload_len<<endl;
                    if(tcp_payload_len != 0)
                    {
                        //cout<<"-------------------------Flow ID: "<<value->ID<<"-----------------------------\n";
                        //cout<<*ip1<<":"<<port1<<" --> "<<*ip2<<":"<<port2<<endl;
                        value->handleTCPPacket(ip1, port1, ip2, port2, tcp_payload, tcp_payload_len, tcphdr.getSeq());
                    }

                }
                else
                {
                    //cout<<"this pkt is skiped\n";
                    return;     //skip this packet
                }
            }
        }
        else if(ip6hdr.getNextHeader() == 6)    //If it's TCP
        {
            TCPHdr tcphdr = TCPHdr(packet + 14 + 40);

            uint8_t t[16];
            ip6hdr.getSrcIP(t);
            IPv6Addr *ip1 = new IPv6Addr(t);
            ip6hdr.getDestIP(t);
            IPv6Addr *ip2 = new IPv6Addr(t);
            uint16_t port1 = tcphdr.getSrcPort();
            uint16_t port2 = tcphdr.getDestPort();

            FlowKey key = FlowKey(ip1, port1, ip2, port2);
            FlowInfoPtr value = flowMgr.findFlow(key);
            /*
                        if(value)
                            cout<<"ptr is not empty\n";
                        else
                            cout<<"ptr is empty\n";
            */
            //manage flow
            //copy from corresponding part of ipv4
            if(!value && tcphdr.isSYN() && !tcphdr.isACK())     //tcp handshake step 1
            {
                value = flowMgr.addNewFlow(key);
                cout<<"new flow added  "<<endl;
            }
            else if(value && value->getStatus() == TCP_HANDSHAKING && tcphdr.isSYN() && tcphdr.isACK())     //tcp handshake step 2
            {
                value->statusChange(TCP_WORKING);
                cout<<"flow changed to tcp_working\n";
            }
            else if(value && value->getStatus() == TCP_WORKING && tcphdr.isFIN())
            {
                value->statusChange(TCP_TERMINATING);
                cout<<"flow changed to tcp_terminating\n";
            }
            else if(value && value->getStatus() == TCP_TERMINATING && tcphdr.isFIN())
            {
                flowMgr.deleteFlow(key);
                cout<<"flow deleted normally\n";
                return;
            }
            else if(value && tcphdr.isRST())
            {
                flowMgr.deleteFlow(key);
                cout<<"flow deleted c'z reseted\n";
            }
            else if(value && (value->getStatus() == TCP_WORKING || value->getStatus() == TCP_TERMINATING))
            {
                //handle tcp payload
                const uint8_t* tcp_payload = packet + 14 + 40 + tcphdr.getHL();
                unsigned int tcp_payload_len = ip6hdr.getPayloadLen() - tcphdr.getHL();
                cout<<"tcphdr length="<<tcphdr.getHL()<<endl;
                cout<<"tcp_payload_len="<<tcp_payload_len<<endl;
                if(tcp_payload_len != 0)
                {
                    // cout<<"-------------------------Flow ID: "<<value->ID<<"-----------------------------\n";
                    // cout<<*ip1<<":"<<port1<<" --> "<<*ip2<<":"<<port2<<endl;
                    value->handleTCPPacket(ip1, port1, ip2, port2, tcp_payload, tcp_payload_len, tcphdr.getSeq());
                }

            }
            else
            {
                //cout<<"this pkt is skiped\n";
                return;     //skip this packet
            }
        }
    }
}

void* sslfile(void* arg)//Temp by Cong Liu
{
    char *filepath = NULL;
    filepath = getenv("SSLKEYLOGFILE");  //for windows_nt
    printf("file: %s \n", filepath);
    if (strlen(filepath) <= 0)
    {
        puts("Error reading SSLKEYLOGFILE, quit thread...");
        return NULL;
    }

    FILE *fin = fopen(filepath, "r");
    if (fin)
    {
        char buf[1000];
        while (true)
        {
            if (fgets(buf, 999, fin))
            {
                //printf("SSLKEYLOG: ");
                //puts(buf);
                if (memcmp(buf, "CLIENT", 6) == 0)
                {
                    char buf2[100];
                    char cr[200] = {0};
                    char ms[200] = {0};
                    sscanf(buf, "%s %s %s", buf2, cr, ms);
                    addMasterSecret(cr, ms);
                }
            }
            else
            {
                //printf("NO OUTPUT...\n");
                //sleep(5);
            }
        }
    }

}

int rewrite = 0;

void my_function(int sig)  // can be called asynchronously
{
    if (rewrite) nfqueue_close();
    exit(0);
}

void usage()
{
    puts("Usage: <PROGRAM_NAME> <OPTIONS>");
    puts("options:  -h    show this message");
    puts("          -w    run  nfqueue mode");
    puts("          -pub <PUB_KEY_FILE>    specify public key");
    puts("          -prv <PRV_KEY_FILE>    specify private key");
    exit(0);
}

int main(int argc, char *argv[])
{
    char *pub_key = NULL;
    char *prv_key = NULL;

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-w") == 0)
        {
            rewrite = 1;
        }
        else if (strcmp(argv[i], "-pub") == 0)
        {
            ++i;
            pub_key = argv[i];
            //printf("public_key_file=%s\n", pub_key);
        }
        else if (strcmp(argv[i], "-prv") == 0)
        {
            ++i;
            prv_key = argv[i];
            //printf("private_key_file=%s\n", prv_key);
        }
        else if (strcmp(argv[i], "-h") == 0)
        {
            usage();
        }
        else
        {
            usage();
        }
    }

    signal(SIGINT, my_function);
    pthread_t tid;
    pthread_create(&tid, NULL, sslfile, NULL);

    abe_init(pub_key, prv_key);
    /*
    //test abe
    char text[] = "Hello world!";
    char policy[] = "CN and TLS";
    ABEFile r = abe_encrypt((unsigned char*)text, strlen(text), policy);
    printf("abefile.len=%d\n", r.len);
    ABEFile res = abe_decrypt(r.f);
    if (res.f) printf("cpabe decrypt: res=%s\n", res.f);
    else puts("Failed to decrypt!");

    exit(0);
    */

    if (rewrite)  //RUN libnetfilter mode
    {
        int fd = nfqueue_init();
        int rv;
        char buf[4096] __attribute__ ((aligned));
        for (;;)
        {
            if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
            {
                //printf("recv rv=%d\n", rv);
                nfqueue_handle(buf, rv);
                continue;
            }
            if (rv < 0 && errno == ENOBUFS)
            {
                printf("losing packets!\n");
                continue;
            }
            perror("recv failed");
            break;
        }

    }
    //some var that pcap will use
    pcap_t *handle;
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr pkthdr;
    const u_char *packet;
    bpf_program fp;
    char filter_exp[] = "";  //SSH only
    bpf_u_int32 mask;
    bpf_u_int32 net;

    //find the first network device can be used to sniff
    device = pcap_lookupdev(errbuf);

    if(device == NULL)
    {
        //fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        cout<<"Couldn't find default device: "<<errbuf<<endl;
        return 2;
    }
    device = "eth0";    //NOTICE: I assign the device directely!
    //open a pcap transaction
    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if(handle == NULL)
    {
        //fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        cout<<"Couldn't open device "<<device<<" : "<<errbuf<<endl;
        return 2;
    }

    //pcap filter
    //obtain network properties of chosen device
    if(pcap_lookupnet(device, &net, &mask, errbuf) == -1)
    {
        //fprintf(stderr, "Can't get netmask for device %s\n", device);
        cout<<"Can't get netmask for device "<<device<<endl;
        net = 0;
        mask = 0;
    }
    //compile filter expression
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        //fprintf(stderr, "Couldn't parse filter %s:%s\n", filter_exp, pcap_geterr(handle));
        cout<<"Couldn't parse filter "<<filter_exp<<" : "<<pcap_geterr(handle)<<endl;
        return 2;
    }
    //apply filter
    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s:%s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    //start sniff
    pcap_loop(handle, -1, got_packet, NULL);
    /*IPv4Addr IP1 = IPv4Addr(0x01010101);
    IPv4Addr IP2 = IPv4Addr(0x02020202);
    IPv4Addr IP3 = IPv4Addr(0x03030303);
    IPv4Addr IP4 = IPv4Addr(0x04040404);
    FlowKey a = FlowKey(&IP1, 443, &IP2, 444);
    FlowKey b = FlowKey(&IP1, 445, &IP4, 446);
    cout<<(a<a);*/
    //cout<<sizeof(ulong);
}
