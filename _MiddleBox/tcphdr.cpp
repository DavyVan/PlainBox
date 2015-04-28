#include "tcphdr.h"
#include<memory.h>
#include<netinet/in.h>

TCPHdr::TCPHdr(const uint8_t *&input)
{
    //copy TCP header to TCPHder.
    memcpy(&header, input, 20);
    //skip whole TCP header(include options)
    uint16_t len = header.doff*4;
    input+=len;
}

uint16_t TCPHdr::getSrcPort()
{
    uint16_t tmp = ntohs(header.source);
    return tmp;
}

uint16_t TCPHdr::getDestPort()
{
    uint16_t tmp = ntohs(header.dest);
    return tmp;
}

uint32_t TCPHdr::getSeq()
{
    uint32_t ret = ntohl(header.seq);
    return ret;
}

unsigned int TCPHdr::getHL()
{
    return header.doff*4;
}

bool TCPHdr::isSYN()
{
    return header.syn ? true : false;
}

bool TCPHdr::isACK()
{
    return header.ack ? true : false;
}

bool TCPHdr::isRST()
{
    return header.rst ? true : false;
}

bool TCPHdr::isFIN()
{
    return header.fin ? true : false;
}

TCPHdr::~TCPHdr()
{
    //dtor
}
