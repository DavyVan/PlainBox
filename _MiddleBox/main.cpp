#include<pcap.h>
#include<iostream>
#include"ip4hdr.h"
#include"tcphdr.h"
#include<cstdio>
using namespace std;

void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    packet+=14;
    //cout<<packet[0]<<endl;
    printf("%x\n", packet);
    IP4Hdr ip4hdr = IP4Hdr(packet);
    //cout<<packet[0]<<endl;
    printf("%x\n", packet);
    TCPHdr tcphdr = TCPHdr(packet);
    //cout<<packet[0]<<endl;
    printf("%x\n", packet);
    cout<<ip4hdr.getSrcIPstr()<<":"<<tcphdr.getSrcPort();//<<"   "<<ip4hdr.getDestIPstr()<<":"<<tcphdr.getDestPort()<<endl;
    cout<<"44444444444444444\n";
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
