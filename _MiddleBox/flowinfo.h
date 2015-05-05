#ifndef FLOWINFO_H
#define FLOWINFO_H

#include<netinet/in.h>
#include"tlshandler.h"
#include"ipaddr.h"
#include"flowkey.h"

//This will be deleted when move cache to App-layer handler
struct FlowDataNode
{
    unsigned int length;
    uint32_t seq;   //seq of the first byte of this TCP segment(the same as the TCP header)
    uint8_t tcp_payload[2000];
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


/*
* A TCP connection between two socket will be a single flow which has TWO data channel.
*/
class FlowInfo
{
    public:
        //NOTICE: I haven't worked out a good extensible framework that can handle multi application-layer protocol yet
        //friend TLSHandler tlshandler;  //public and friend is more easily to access its functionalities.

        FlowInfo(FlowKey &key);

        FlowKey* getFlowKey();

        FlowStatus getStatus();
        void statusChange(FlowStatus newStatus);

        //FlowDataNode* getFlowData();

        //friend bool operator< (const FlowInfo a, const FlowInfo b);
        //friend bool operator== (const FlowInfo a, const FlowInfo b);
        ~FlowInfo();

    private:
        FlowKey key;
        FlowStatus status;

        /*I will use the link list only. TCPHandler will add ordered new TCP segment to this
        * and TLSHandler will remove used data away from this link list.
        * I will handle the gap between Nodes.
        */
        //FlowDataNode *_1to2;
        //FlowDataNode *_2to1;
        //FlowDataNode *temp_1to2;
        //FlowDataNode *temp_2to1;
};



#endif // FLOWINFO_H
