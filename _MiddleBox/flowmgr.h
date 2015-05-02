#ifndef FLOWMGR_H
#define FLOWMGR_H

#include<map>
#include"flowinfo.h"
#include"flowkey.h"
#include<boost/shared_ptr.hpp>

typedef boost::shared_ptr<FlowInfo> FlowInfoPtr;

class FlowMgr
{
    public:
        FlowMgr();

        /*
        * This function check whether a TCP flow exists once a new packet arrived.
        * If the flow exists, return FlowInfo which describes this flow; or return NULL.
        */
        FlowInfoPtr findFlow(FlowKey key);
        /*THESE functions may have the following overload, but they should be less used.
        bool isFlowExists(FlowInfo flowinfo);
        bool isFlowExists(uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2);
        */

        //Add a new flow when SYN=1, ACK=0 detected.
        void addNewFlow(FlowKey key);

        //When the final FIN=1 detected, delete the flow from FlowMgr.
        void deleteFlow(FlowKey key);

        ~FlowMgr();
    private:
        map<FlowKey, FlowInfoPtr> mp;    //the key's values are NULL/default except IPs and Ports.
};

#endif // FLOWMGR_H
