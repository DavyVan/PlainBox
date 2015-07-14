#ifndef TCPDATASTRUCTURE_H
#define TCPDATASTRUCTURE_H

struct TCPDataNode
{
    unsigned int length;
    uint32_t seq;   //seq of the first byte of this TCP segment(the same as the TCP header)
    uint8_t tcp_payload[70000];
    TCPDataNode *next;
};

enum TCPDataDirection
{
    _1to2,
    _2to1
};

#endif
