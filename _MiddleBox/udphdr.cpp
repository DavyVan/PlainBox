#include<memory.h>
#include "udphdr.h"

UDPHdr::UDPHdr(const uint8_t* input)
{
    memcpy(&header, input, 8);
}

UDPHdr::~UDPHdr()
{
    //dtor
}

uint16_t UDPHdr::getSrcPort()
{
    return ntohs(header.source);
}

uint16_t UDPHdr::getDestPort()
{
    return ntohs(header.dest);
}

uint16_t UDPHdr::getLength()
{
    return ntohs(header.len);
}
