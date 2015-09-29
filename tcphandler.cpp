#include<memory.h>
#include <cstdio>
#include<iostream>
#include "tcphandler.h"
#include"tlshandler.h"
#include"sshhandler.h"
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<net/ethernet.h>
#include<netpacket/packet.h>
#include<net/if.h>
#include<sys/ioctl.h>
#include <errno.h>

using namespace std;

TCPHandler::TCPHandler()
{
    current_seq[0] = 0;
    current_seq[1] = 0;
    next_seq[0] = 0;
    next_seq[1] = 0;

    temp[0] = NULL;
    temp[1] = NULL;

    applayerhandler = NULL;
}

TCPHandler::~TCPHandler()
{
    delete(applayerhandler);
}

int TCPHandler::reAssemblePacket(uint16_t srcPort, uint16_t destPort, const uint8_t *payload, unsigned int length, TCPDataDirection direction, uint32_t seq, FlowKey* flowkey)
{
    //sequence
    if(next_seq[direction] == 0 || next_seq[direction] == seq)
    {
        current_seq[direction] = seq;
        next_seq[direction] = current_seq[direction] + length;

        //construct new TCPDataNode
        TCPDataNode *node = new TCPDataNode();
        node->length = length;
        node->seq = seq;
        node->next = NULL;
        memcpy(node->tcp_payload, payload, length);

        //check if the rest of temp is ordered.
        TCPDataNode *p = temp[direction];
        TCPDataNode *q = node;
        uint32_t p_seq = next_seq[direction];
        while(p != NULL && p->seq == p_seq)
        {
            q->next = p;
            p_seq += p->length;
            q = q->next;
            p = p->next;
        }
        q->next = NULL;
        temp[direction] = p;
        next_seq[direction] = p_seq;

        //application layer processing
        if(applayerhandler == NULL && (srcPort == 443 || destPort == 443))
        {
            applayerhandler = new TLSHandler();
        }
        else if(applayerhandler == NULL && (srcPort == 22 || destPort == 22))
            applayerhandler = new SSHHandler();
        else if(srcPort == 80 || destPort == 80)
        {
            TCPDataNode *t;
            while(node)
            {
                t = node->next;
                delete node;
                node = t;
            }
        }
        if(applayerhandler != NULL) {
            applayerhandler->parse(node, direction, flowkey);
            if (applayerhandler->abe.len > 0) {
                abe = applayerhandler->abe;
                applayerhandler->abe.len = 0;
                return applayerhandler->abe.len;
            }
        }
    }
    else if(next_seq[direction] < seq)
    {
        //dis-ordered
        //construct TCPDataNode
        TCPDataNode *node = new TCPDataNode();
        node->length = length;
        node->seq = seq;
        node->next = NULL;
        memcpy(node->tcp_payload, payload, length);

        //insert it into temp
        TCPDataNode *q = NULL;
        TCPDataNode *p = temp[direction];
        while(p != NULL && node->seq >= p->seq)
        {
            if(node->seq == p->seq)
            {
                cout<<"This packet is skiped because there is a same packet(same seq)"<<endl;
                delete node;
                return 0;
            }
            q = p;
            p = p->next;
        }
        if(q == NULL)
            temp[direction] = node;
        else
            q->next = node;
        node->next = p;
    }
    return 0;
}

int TCPHandler::handleKeys(const uint8_t *payload, unsigned int length)
{
    if (applayerhandler) {
        printf("TCP::handleKEYS! len=%d\n", length);
        ABEFile abe = abe_decrypt(payload);
        printf("after ABE_DEC: len=%d\n", abe.len);
        applayerhandler->handleKeys(abe.f, abe.len);
        delete []abe.f;
    }
}


static int fd = 0;

static void init_socket()
{
    fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
}

int sendTCPWithOption(const uint8_t* iphead, ABEFile abe, int c2s)
{
    if (fd == 0) {
        init_socket();
    }
    uint8_t p[2000] = {0};
    memcpy(p, iphead, 20);//IPHEAD
    iphdr* iph = (iphdr*)p;

    iph->protocol = 6;  //for ESP

    int len = htons(iph->tot_len);
    for (int i = 0; i < 20; ++i) printf("%02x ", p[i]);printf("\n");
    printf("len=%d\n", len);
    printf("%s\n", c2s?"CLIENT->SERVER":"SERVER->CLIENT");
    if (!c2s) {
        uint32_t t = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = t;
    }
    int newpacket = 0;
    if (len + abe.len > 1450) {
        printf("PACKET TOO LONG, SEND a NEW PACKET!\n");
        newpacket = 1;
    }
    memcpy(p+20, iphead+20, 20);//TCP
    tcphdr *tcph = (tcphdr*)(p+20);

    if (!c2s) {
        uint16_t t = tcph->source;
        tcph->source = tcph->dest;
        tcph->dest = t;
    }

    printf("TCPH_LEN=%d\n", tcph->doff*4);
    int optl = (tcph->doff*4) - 20;
    int tot = abe.len;
    int p_pos = 40;
    int a_pos = 0;
    /*
    while (tot > 0) {
        int cur = tot;
        if (cur > 250) cur = 250;
        p[p_pos++] = 250;//TYPE
        p[p_pos++] = cur + 2;
        memcpy(p + p_pos, abe.f + a_pos, cur);
        p_pos += cur;
        a_pos += cur;
        tot -= cur;
    };*/
    p[p_pos++] = 250;//TYPE
    p[p_pos++] = 3;//LEN
    p[p_pos++] = 1;//VALUE
    memcpy(p + p_pos, iphead+40, optl);
    p_pos += optl;
    while ((p_pos-40)%4 != 0) p[p_pos++]=0;
    printf("new header length=%d\n", p_pos-20);
    tcph->doff = (p_pos-20) / 4;

    memcpy(p + p_pos, abe.f, abe.len);
    p_pos += abe.len;

    iph->tot_len = htons(p_pos);

    len = p_pos;

    //fix checksum
    tcph->check = 0;
    tcph->seq = tcph->ack_seq = 0;



	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	memcpy(&dest.sin_addr, p + 16, 4);
	printf("addr=%x\n", dest.sin_addr);
    if (sendto(fd, p, len, 0, (struct sockaddr *)&dest, sizeof(dest)) != len) {
        fprintf(stderr, "socket4 send: Failed to send ipv4 packet len=%d %s\n", len, strerror(errno));
    }
    printf("sendto %s  %d bytes\n", inet_ntoa(dest.sin_addr), len);
    return 0;
}

static int fd_PF_PACKET = 0;

static void init_socket_PF_PACKET()
{
    fd_PF_PACKET = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
}

int sendTCPWithOption_PF_PACKET(const uint8_t* ethhead, ABEFile abe, int c2s)
{
    if(fd_PF_PACKET == 0)
        init_socket_PF_PACKET();
    uint8_t p[2000] = {0};
    memcpy(p, ethhead, 14); //ETH header
    ether_header* ethh = (ether_header*) p;
    ethh->ether_type = ntohs(ETHERTYPE_IP);
    uint8_t ethsaddr[6] = {0x00, 0x0c, 0x29, 0x53, 0x1a, 0x6e};
    uint8_t ethdaddr[6] = {0x00, 0x0c, 0x29, 0x95, 0x16, 0xef};
    memcpy(ethh->ether_shost, ethsaddr, 6);
    memcpy(ethh->ether_dhost, ethdaddr, 6);

    memcpy(p+14, ethhead+14, 20);   //IP header
    iphdr* iph = (iphdr*)(p+14);
    iph->protocol = 6;
    int len = htons(iph->tot_len);
    if(!c2s)
    {
        //reverse eth mac addr
        uint8_t t[6];
        memcpy(t, ethh->ether_shost, 6);
        memcpy(ethh->ether_shost, ethh->ether_dhost, 6);
        memcpy(ethh->ether_dhost, t, 6);

        //reverse ip addr
        uint32_t tt = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = tt;
    }
    memcpy(p+14+20, ethhead+14+20, 20); //TCP header
    tcphdr *tcph = (tcphdr*)(p+14+20);

//    int optl = 0;
    int tot = abe.len;
    int p_pos = 40+14;
//    int a_pos = 0;

    p[p_pos++] = 250;
    p[p_pos++] = 3;
    p[p_pos++] = 1;
//    memcpy(p + p_pos, ethhead+14+40, optl);
//    p_pos += optl;
//    while((p_pos-40-14)%4 != 0)
//        p[p_pos++] = 0;
//    tcph->doff = (p_pos-20)/4;

    memcpy(p + p_pos, abe.f, abe.len);
    p_pos += abe.len;

    iph->tot_len = htons(p_pos - 14);

    len = p_pos;

    //fix checksum
    tcph->check = 0;
    tcph->seq = tcph->ack_seq = 0;

    //ip checksum
    iph->check = 0;
    uint16_t *buff = (uint16_t*)(p+14);
    unsigned int checksum = 0;
    for(int i = 0; i < 10; i++)
        checksum += buff[i];
    checksum=(checksum>>16)+(checksum & 0xffff);
    checksum+=(checksum>>16);
    iph->check = ~checksum;

    sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_protocol = ETHERTYPE_IP;
    ifreq ifstruct;
    strcpy(ifstruct.ifr_name, "eth1");
    ioctl(fd_PF_PACKET, SIOCGIFINDEX, &ifstruct);
    dest.sll_ifindex = ifstruct.ifr_ifindex;
    memcpy(dest.sll_addr, ethh->ether_dhost, 6);
    dest.sll_halen = 6;
    if(sendto(fd_PF_PACKET, p, len, 0, (sockaddr*)&dest, sizeof(dest)) != len)
    {
        printf("socket4 send: Failed to send ipv4 packet len=%d %s\n", len, strerror(errno));
    }
    in_addr addr;
    addr.s_addr = iph->daddr;
    printf("sendto %s %d bytes\n", inet_ntoa(addr), len);
    return 0;
}

int sendUDP(const uint8_t* iphead, ABEFile abe, int c2s)
{
    if(fd_PF_PACKET == 0)
        init_socket_PF_PACKET();
    uint8_t p[2000] = {0};
    ether_header *ethh = (ether_header*)p;
    ethh->ether_type = ntohs(ETHERTYPE_IP);
    uint8_t ethsaddr[6] = {0x00, 0x0c, 0x29, 0x53, 0x1a, 0x6e};
    uint8_t ethdaddr[6] = {0x00, 0x0c, 0x29, 0x95, 0x16, 0xef};
    memcpy(ethh->ether_shost, ethsaddr, 6);
    memcpy(ethh->ether_dhost, ethdaddr, 6);

    memcpy(p+14, iphead, 20);   //IP header
    iphdr *iph = (iphdr*)(p+14);
    iph->protocol = 17;
    int len = htons(iph->tot_len);
    if(!c2s)
    {
        uint32_t t = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = t;
    }

    udphdr *udph = (udphdr*)(p+14+20);
    udph->source = htons(6666);
    udph->dest = htons(6666);
    udph->check = 0;

    int tot = abe.len;
    int p_pos = 14+20+8;

    memcpy(p + p_pos, abe.f, abe.len);
    p_pos += abe.len;

    iph->tot_len = htons(p_pos - 14);
    udph->len = htons(p_pos-14-20);

    len = p_pos;

    //ip checksum
    iph->check = 0;
    uint16_t *buff = (uint16_t*)(p+14);
    unsigned int checksum = 0;
    for(int i = 0; i < 10; i++)
        checksum += buff[i];
    checksum=(checksum>>16)+(checksum & 0xffff);
    checksum+=(checksum>>16);
    iph->check = ~checksum;

    sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_protocol = ETHERTYPE_IP;
    ifreq ifstruct;
    strcpy(ifstruct.ifr_name, "eth1");
    ioctl(fd_PF_PACKET, SIOCGIFINDEX, &ifstruct);
    dest.sll_ifindex = ifstruct.ifr_ifindex;
    memcpy(dest.sll_addr, ethh->ether_dhost, 6);
    dest.sll_halen = 6;
    if(sendto(fd_PF_PACKET, p, len, 0, (sockaddr*)&dest, sizeof(dest)) != len)
    {
        printf("socket4 send: Failed to send ipv4 packet len=%d %s\n", len, strerror(errno));
    }
    in_addr addr;
    addr.s_addr = iph->daddr;
    printf("sendto %s %d bytes\n", inet_ntoa(addr), len);
    return 0;
}
