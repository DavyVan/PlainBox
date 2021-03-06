#ifndef FLOWINFO_H
#define FLOWINFO_H

#include<netinet/in.h>
#include<boost/shared_ptr.hpp>
#include<boost/enable_shared_from_this.hpp>
#include"ipaddr.h"
#include"flowkey.h"
#include"tcphandler.h"
#include "abe.h"

enum FlowStatus     //prefix "TCP_" can be removed
{
    TCP_HANDSHAKING,
    TCP_WORKING,
    TCP_TERMINATING
};

/*
* A TCP connection between two socket will be a single flow which has TWO data channel.
*/
class FlowInfo: public boost::enable_shared_from_this<FlowInfo>
{
    public:
        //NOTICE: I haven't worked out a good extensible framework that can handle multi application-layer protocol yet
        //friend TLSHandler tlshandler;  //public and friend is more easily to access its functionalities.
        static unsigned int flow_counter;
        const unsigned int ID;

        FlowInfo(FlowKey &key);

        FlowKey* getFlowKey();

        FlowStatus getStatus();
        void statusChange(FlowStatus newStatus);
        //Call TCPHandler.reAssemblePacket() and decide which direction
        int handleTCPPacket(IPAddr *srcIP, uint16_t srcPort, IPAddr *destIP, uint16_t destPort, const uint8_t *payload, unsigned int length, uint32_t seq);
        
        int handleKeys(const uint8_t *payload, unsigned int length);

        boost::shared_ptr<FlowInfo> getThis(){return shared_from_this();};

        void print(TCPDataDirection direction);



        //FlowDataNode* getFlowData();

        //friend bool operator< (const FlowInfo a, const FlowInfo b);
        //friend bool operator== (const FlowInfo a, const FlowInfo b);
        ~FlowInfo();

        ABEFile abe;
    //private:
        FlowKey key;
        FlowStatus status;
        TCPHandler tcphandler;

};

typedef boost::shared_ptr<FlowInfo> FlowInfoPtr;

#endif // FLOWINFO_H
