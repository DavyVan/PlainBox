#ifndef FLOWMGR_H
#define FLOWMGR_H

#include<map>
#include"flowinfo.h"
#include"flowkey.h"



typedef map<unsigned long, FlowInfoPtr>::iterator map_it;

class FlowMgr
{
    public:
        FlowMgr();

        /*
        * This function check whether a TCP flow exists once a new packet arrived.
        * If the flow exists, return FlowInfo which describes this flow; or return NULL.
        */
        FlowInfoPtr findFlow(FlowKey &key);

        //Add a new flow when SYN=1, ACK=0 detected.
        FlowInfoPtr addNewFlow(FlowKey &key);

        //When the final FIN=1 detected, delete the flow from FlowMgr.
        void deleteFlow(FlowKey &key);

        ~FlowMgr();
    private:
        map<unsigned long, FlowInfoPtr> mp;    //the key's values are NULL/default except IPs and Ports.
};

#endif // FLOWMGR_H
