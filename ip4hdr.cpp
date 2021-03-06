#include "ip4hdr.h"
#include<memory.h>
#include<arpa/inet.h>

IP4Hdr::IP4Hdr(const uint8_t* input)
{
    //copy IP header to IP4Hder. Notice that Ethernet header was ignored.
    memcpy(&header, input, 20);
    //skip whole IP header(include options)*****DONT DO THIS HERE
    //uint16_t len = header.ihl*4;
    //input+=len;
}

unsigned int IP4Hdr::getHL()
{
    return header.ihl*4;
}

uint32_t IP4Hdr::getSrcIP()
{
    return header.saddr;
}

string IP4Hdr::getSrcIPstr()
{
    char t[INET_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &header.saddr, t, INET_ADDRSTRLEN);
    return t;
}

uint32_t IP4Hdr::getDestIP()
{
    return header.daddr;
}

string IP4Hdr::getDestIPstr()
{
    char t[INET_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &header.daddr, t, INET_ADDRSTRLEN);
    return t;
}

uint16_t IP4Hdr::getTotalLen()
{
    uint16_t ret = ntohs(header.tot_len);
    return ret;
}

uint8_t IP4Hdr::getProtocol()
{
    return header.protocol;
}

IP4Hdr::~IP4Hdr()
{
    //dtor
}
