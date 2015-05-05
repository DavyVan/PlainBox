#ifndef FLOWINFO_H
#define FLOWINFO_H

#include<netinet/in.h>
#include"tlshandler.h"
#include"ipaddr.h"
#include"flowkey.h"


enum FlowStatus
{
    TCP_HANDSHAKING,
    TCP_WORKING,
    TCP_TERMINATING
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
};



#endif // FLOWINFO_H
