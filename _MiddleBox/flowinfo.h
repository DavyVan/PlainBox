#ifndef FLOWINFO_H
#define FLOWINFO_H

#include<netinet/in.h>

class FlowInfo
{
    public:
        FlowInfo(IP4Hdr ip4hdr, TCPHdr tcphdr);

        uint32_t getIP1();
        char* getIP1Str();
        uint32_t getIP2();
        char* getIP2Str();
        uint16_t getPort1();
        uint16_t getPort2();

        int getStatus();

        FlowDataNode* getFlowData();

        friend bool <
        friend bool ==
        ~FlowInfo();
    private:
        uint32_t IP1;
        uint32_t IP2;
        uint16_t Port1;
        uint16_t Port2;
        int status;
        FlowDataNode *_1to2;
        FlowDataNode *_2to1;
};

struct FlowDataNode
{
    unsigned int length;
    uint8_t *ptr;
    FlowDataNode *next;
};

enum FlowStatus
{
    TCP_HANDSHAKING,
    TCP_WORKING,
    TCP_TERMINATING
};

enum FlowDataDirection
{
    _1to2,
    _2to1
};

#endif // FLOWINFO_H
