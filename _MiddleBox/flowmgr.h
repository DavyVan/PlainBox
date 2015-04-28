#ifndef FLOWMGR_H
#define FLOWMGR_H

#include<map>
#include"flowinfo.h"

class FlowMgr
{
    public:
        FlowMgr();

        /*
        * This function check whether a TCP flow exists once a new packet arrived.
        * If the flow exists, return FlowInfo which describes this flow; or return NULL.
        */
        FlowInfo* isFlowExists(IP4Hdr ip4hdr, TCPHdr tcphdr);
        /*THESE functions may have the following overload, but they should be less used.
        bool isFlowExists(FlowInfo flowinfo);
        bool isFlowExists(uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2);
        */

        //Add a new flow when SYN=1, ACK=0 detected.
        void addNewFlow(IP4Hdr ip4hdr, TCPHdr tcphdr);

        //According to the flags in TCP header, change flow status.
        void statusChange(IP4Hdr ip4hdr, TCPHdr tcphdr, int newStatus);
        void statusChange(FlowInfo flowinfo, int newStatus);    //FlowStatus in flowinfo.h

        //When the final FIN=1 detected, delete the flow from FlowMgr.
        void deleteFlow(IP4Hdr ip4hdr, TCPHdr tcphdr);
        void deleteFlow(FlowInfo flowinfo);

        //Call isFlowExists first!
        FlowInfo getFlowInfo();

        ~FlowMgr();
    private:
        map<FlowInfo, FlowInfo> Map;    //the key's values are NULL/default except IPs and Ports.
};

#endif // FLOWMGR_H
