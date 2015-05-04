#include<pcap.h>
#include<iostream>
#include<cstdio>
#include<memory.h>
#include"ip4hdr.h"
#include"tcphdr.h"
#include"flowkey.h"
#include"flowmgr.h"
#include"flowinfo.h"
#include"ipaddr.h"
using namespace std;

FlowMgr flowMgr = FlowMgr();

//Do something when we get a new packet
void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    //get IP and TCP headers, but above all we must look which IP protocol version will use.
    uint8_t ip_version;
    memcpy(&ip_version, packet+14, 8);
    ip_version>>=4;
    if(ip_version == 4)
    {
        //ipv4
        IP4Hdr ip4hdr = IP4Hdr(packet + 14);
        TCPHdr tcphdr = TCPHdr(packet + 14 + ip4hdr.getHL());   //NOTICE: we only sniff tcp packet by using pcap filter
        cout<<ip4hdr.getSrcIPstr()<<":"<<tcphdr.getSrcPort()<<"   "<<ip4hdr.getDestIPstr()<<":"<<tcphdr.getDestPort()<<endl;

        //Check whether the flow exists or not
        IPv4Addr ip1 = IPv4Addr(ip4hdr.getSrcIP());
        uint16_t port1 = tcphdr.getSrcPort();
        IPv4Addr ip2 = IPv4Addr(ip4hdr.getDestIP());
        uint16_t port2 = tcphdr.getDestPort();
        FlowKey key = FlowKey(&ip1, port1, &ip2, port2);
        cout<<key.getIP1()->getAddr_str()<<endl;

        FlowInfoPtr value = flowMgr.findFlow(key);
    }
    else if(ip_version == 6)
    {
        //TODO: ipv6
    }

}

int main(int argc, char *argv[])
{
    //some var that pcap will use
    pcap_t *handle;
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr pkthdr;
    const u_char *packet;
    bpf_program fp;
    char filter_exp[] = "tcp";  //tcp only
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
    pcap_loop(handle, 130, got_packet, NULL);
}
