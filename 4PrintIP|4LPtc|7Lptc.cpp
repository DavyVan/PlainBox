/*
Sniff 200 packets and find which transport layer protocol they carried in IP header;
which application layer protocol they carried by port.
Print everything above along with IP addr.
*/

#include<stdio.h>
#include<pcap.h>
#include<netinet/in.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define UDP_HDR_LEN 16

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

#define IP_HL(ip) (((ip)->ip_ver) & 0x0f)
#define IP_V(ip) (((ip)->ip_ver) >> 4)

#define TCP_OFF(tcp) (((tcp)->tcp_offx2 & 0xf0) >> 4)

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)

struct eth_hdr
{
    u_char eth_dest[ETHER_ADDR_LEN];
    u_char eth_src[ETHER_ADDR_LEN];
    u_short eth_type;
};

struct ip_addr
{
    u_char a;
    u_char b;
    u_char c;
    u_char d;
};

struct ip_hdr
{
    u_char ip_ver;
    u_char ip_typeofservice;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_protocol;
    u_short ip_sum;
    ip_addr ip_src, ip_dest;
};

//typedef u_int tcp_seq;

struct tcp_hdr
{
    u_short tcp_srcport;
    u_short tcp_destport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
    u_char tcp_flags;
    u_short tcp_window;
    u_short tcp_sum;
    u_short tcp_urp;
};

struct udp_hdr
{
    u_short udp_srcport;
    u_short udp_destport;
    u_short udp_totallen;
    u_short udp_sum;
};

const eth_hdr *ethernet;
const ip_hdr *ip;
const tcp_hdr *tcp;
const udp_hdr *udp;
const u_char *payload;

u_short src;
u_short dest;

u_int size_ip;
u_int size_tcp;

bool test_port(u_short wellknown, u_short src, u_short dest)
{
    if(src == wellknown || dest == wellknown)
        return true;
    return false;
}

void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    ethernet = (eth_hdr *) packet;
    ip = (ip_hdr*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20)
    {
        printf(" * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }



    switch(ip->ip_protocol)
    {
        case 6:
            printf("[TCP-");
            tcp = (tcp_hdr*) (packet + SIZE_ETHERNET + size_ip);
            size_tcp = TCP_OFF(tcp)*4;
            if(size_tcp < 20)
            {
                printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            src = ntohs(tcp->tcp_srcport);
            dest = ntohs(tcp->tcp_destport);
            if(test_port(80, src, dest))
                printf("HTTP]  ");
            else if(test_port(443, src, dest))
                printf("HTTPS]  ");
            else
                printf("]  ");
            printf("From %u.%u.%u.%u:%u To %u.%u.%u.%u:%u\n", ip->ip_src.a,ip->ip_src.b,ip->ip_src.c,ip->ip_src.d,src,ip->ip_dest.a,ip->ip_dest.b,ip->ip_dest.c,ip->ip_dest.d,dest);
            //payload = (const u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
            //printf("%s\n", payload);
            break;
        case 1:
            printf("[ICMP]  ");
            printf("From %u.%u.%u.%u To %u.%u.%u.%u\n", ip->ip_src.a,ip->ip_src.b,ip->ip_src.c,ip->ip_src.d,ip->ip_dest.a,ip->ip_dest.b,ip->ip_dest.c,ip->ip_dest.d);
            break;
        case 17:
            printf("[UDP-");
            udp = (udp_hdr*) (packet + SIZE_ETHERNET + size_ip);
            src = ntohs(udp->udp_srcport);
            dest = ntohs(udp->udp_destport);
            if(test_port(53, src, dest))
                printf("DNS]  ");
            else
                printf("]  ");
            printf("From %u.%u.%u.%u:%u To %u.%u.%u.%u:%u\n", ip->ip_src.a,ip->ip_src.b,ip->ip_src.c,ip->ip_src.d,src,ip->ip_dest.a,ip->ip_dest.b,ip->ip_dest.c,ip->ip_dest.d,dest);
            //payload = (const u_char *) (packet + SIZE_ETHERNET + size_ip + UDP_HDR_LEN);
            break;
        case 56:
            printf("[TLS]  ");
            printf("From %u.%u.%u.%u To %u.%u.%u.%u\n", ip->ip_src.a,ip->ip_src.b,ip->ip_src.c,ip->ip_src.d,ip->ip_dest.a,ip->ip_dest.b,ip->ip_dest.c,ip->ip_dest.d);
            break;
        default:
            printf("[%u]  ", ip->ip_protocol);
            printf("From %u.%u.%u.%u To %u.%u.%u.%u\n", ip->ip_src.a,ip->ip_src.b,ip->ip_src.c,ip->ip_src.d,ip->ip_dest.a,ip->ip_dest.b,ip->ip_dest.c,ip->ip_dest.d);
            break;
    }




}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr header;
    const u_char *packet;
    bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    device = pcap_lookupdev(errbuf);
    if(device == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }

    handle = pcap_open_live(device, BUFSIZ, 0, 0, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return 2;
    }

    if(pcap_lookupnet(device, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s:%s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s:%s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    //packet = pcap_next(handle, &header);
    pcap_loop(handle, 200, got_packet, NULL);

    /*ethernet = (eth_hdr *) packet;
    ip = (ip_hdr*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20)
    {
        printf(" * Invalid IP header length: %u bytes\n", size_ip);
        return 2;
    }

    tcp = (tcp_hdr*) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TCP_OFF(tcp)*4;
    if(size_tcp < 20)
    {
        printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
        return 2;
    }

    payload = (const u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

    printf("from %u.%u.%u.%u to %u.%u.%u.%u\n", ip->ip_src.a,ip->ip_src.b,ip->ip_src.c,ip->ip_src.d,ip->ip_dest.a,ip->ip_dest.b,ip->ip_dest.c,ip->ip_dest.d);*/
    pcap_close(handle);
}
