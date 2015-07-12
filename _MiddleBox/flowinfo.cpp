#include<iostream>
#include "flowinfo.h"

unsigned int FlowInfo::flow_counter = 0;

FlowInfo::FlowInfo(FlowKey &key_)
    :key(key_.getIP1(), key_.getPort1(), key_.getIP2(), key_.getPort2()),
    status(TCP_HANDSHAKING),
    ID(++flow_counter)
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

int FlowInfo::handleTCPPacket(IPAddr *srcIP, uint16_t srcPort, IPAddr *destIP, uint16_t destPort, const uint8_t *payload, unsigned int length, uint32_t seq)
{
    //decide direction
    TCPDataDirection direction;
    if(typeid(*srcIP) == typeid(IPv4Addr) && typeid(*key.getIP1()) == typeid(IPv4Addr))
    {
        //std::cout<<"------------start handle TCP packet-----------------\n";
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

    int ret = tcphandler.reAssemblePacket(srcPort, destPort, payload, length, direction, seq, &key);
    if (tcphandler.abe.len > 0) {
        abe = tcphandler.abe;
        tcphandler.abe.len = 0;
    }
    return ret;
}

int FlowInfo::handleKeys(const uint8_t *payload, unsigned int length)
{
    tcphandler.handleKeys(payload, length);
}

void FlowInfo::print(TCPDataDirection direction)
{
    key.print(direction);
    return;
}
