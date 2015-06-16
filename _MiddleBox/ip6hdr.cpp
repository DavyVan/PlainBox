#include "ip6hdr.h"
#include<memory.h>

IP6Hdr::IP6Hdr(const uint8_t* const input)
{
    memcpy(&header, input, 40);
}

IP6Hdr::~IP6Hdr()
{
    //dtor
}

void IP6Hdr::getSrcIP(uint8_t* destArray)
{
    memcpy(destArray, header.ip6_src.__in6_u.__u6_addr8, 16);
}

void IP6Hdr::getDestIP(uint8_t* destArray)
{
    memcpy(destArray, header.ip6_dst.__in6_u.__u6_addr8, 16);
}

uint16_t IP6Hdr::getPayloadLen()
{
    uint16_t ret = ntohs(header.ip6_ctlun.ip6_un1.ip6_un1_plen);
    return ret;
}

uint8_t IP6Hdr::getNextHeader()
{
    return header.ip6_ctlun.ip6_un1.ip6_un1_nxt;
}
