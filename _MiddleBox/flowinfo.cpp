#include<iostream>
#include "flowinfo.h"

FlowInfo::FlowInfo(FlowKey &key_)
    :key(key_.getIP1(), key_.getPort1(), key_.getIP2(), key_.getPort2())
    , status(TCP_HANDSHAKING)
{

}

FlowInfo::~FlowInfo()
{
    //dtor
}

FlowKey* FlowInfo::getFlowKey()
{
    return &key;
}

FlowStatus FlowInfo::getStatus()
{
    return status;
}

void FlowInfo::statusChange(FlowStatus newStatus)
{
    status = newStatus;
}

void FlowInfo::handleTCPPacket(IPAddr *srcIP, uint16_t srcPort, IPAddr *destIP, uint16_t destPort, const uint8_t *payload, unsigned int length, uint32_t seq)
{
    //decide direction
    TCPDataDirection direction;
    if(typeid(*srcIP) == typeid(IPv4Addr) && typeid(*key.getIP1()) == typeid(IPv4Addr))
    {
        std::cout<<"------------start handle TCP packet-----------------\n";
        if(equalto(srcIP->getAddr_raw(), key.getIP1()->getAddr_raw(), 4))
        {
            direction = _1to2;
        }
        else if(equalto(srcIP->getAddr_raw(), key.getIP2()->getAddr_raw(), 4))
        {
            direction = _2to1;
        }
    }
    else if(typeid(*srcIP) == typeid(IPv6Addr) && typeid(*key.getIP1()) == typeid(IPv6Addr))
    {
        if(equalto(srcIP->getAddr_raw(), key.getIP1()->getAddr_raw(), 16))
            direction = _1to2;
        else if(equalto(srcIP->getAddr_raw(), key.getIP2()->getAddr_raw(), 16))
            direction = _2to1;
    }

    tcphandler.reAssemblePacket(srcPort, destPort, payload, length, direction, seq);
}
