//read packets from eth0 and print its src_ip & dest_ip and protocol atop IP

#include<stdio.h>
#include<pcap.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

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
    u_char a,b,c,d;
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

const eth_hdr *ethernet;
const ip_hdr *ip;
const tcp_hdr *tcp;
const u_char *payload;

u_int size_ip;
u_int size_tcp;

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

    printf("from %u.%u.%u.%u to %u.%u.%u.%u", ip->ip_src.a,ip->ip_src.b,ip->ip_src.c,ip->ip_src.d,ip->ip_dest.a,ip->ip_dest.b,ip->ip_dest.c,ip->ip_dest.d);

    switch(ip->ip_protocol)
    {
        case 6:
            printf("  [TCP]\n");
            break;
        case 1:
            printf("  [ICMP]\n");
            break;
        case 17:
            printf("  [UDP]\n");
            break;
        default:
            printf("  [%u]", ip->ip_protocol);
    }

    /*tcp = (tcp_hdr*) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TCP_OFF(tcp)*4;
    if(size_tcp < 20)
    {
        printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    payload = (const u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);*/


}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr header;
    const u_char *packet;

    device = pcap_lookupdev(errbuf);
    if(device == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }

    handle = pcap_open_live(device, BUFSIZ, 0, 3000, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
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
}
