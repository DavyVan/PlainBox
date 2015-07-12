#include<memory.h>
#include <cstdio>
#include<iostream>
#include "tcphandler.h"
#include"tlshandler.h"
#include"sshhandler.h"
#include<netinet/ip.h>
#include<netinet/tcp.h>
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
        if(applayerhandler == NULL && (srcPort == 22 || destPort == 22))
            applayerhandler = new SSHHandler();
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

