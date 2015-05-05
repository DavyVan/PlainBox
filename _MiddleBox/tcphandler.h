#ifndef TCPHANDLER_H
#define TCPHANDLER_H

#include"flowinfo.h"

struct TCPDataNode
{
    unsigned int length;
    uint32_t seq;   //seq of the first byte of this TCP segment(the same as the TCP header)
    uint8_t tcp_payload[2000];
    TCPDataNode *next;
};

enum TCPDataDirection
{
    _1to2,
    _2to1
};

/*
* TCPHandler is aim to re-assemble TCP segment into a link list
* which is consist of FlowDataNode and its head is in FlowInfo.
* Dis-ordered segment will temperarily stay in FlowInfo's own temp link list(temp_1to2/temp_2to1).
*/
class TCPHandler
{
    public:
        TCPHandler();

        //Maybe static
        void newPacket(FlowInfo flowinfo, uint8_t *payload);

        ~TCPHandler();
    private:
        //dis-ordered segment will be stored here.
        TCPDataNode *temp_1to2;
        TCPDataNode *temp_2to1;
};

#endif // TCPHANDLER_H
