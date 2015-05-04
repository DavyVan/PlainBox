#include<typeinfo>
#include "flowkey.h"
#include"ipaddr.h"

FlowKey::FlowKey(IPAddr *ip1, uint16_t port1, IPAddr *ip2, uint16_t port2)
{
    if(ip1 < ip2)
    {
        IP1 = ip1;
        IP2 = ip2;
        Port1 = port1;
        Port2 = port2;
    }
    else
    {
        IP2 = ip1;
        IP1 = ip2;
        Port2 = port1;
        Port1 = port2;
    }
}

FlowKey::~FlowKey()
{
    //dtor
}

bool operator< (const FlowKey &a, const FlowKey &b)
{
    if(typeid(a.getIP1()) == typeid(IPv4Addr) && typeid(b.getIP1()) == typeid(IPv6Addr))
        return true;
    else if(typeid(a.getIP1()) == typeid(IPv6Addr) && typeid(b.getIP1()) == typeid(IPv4Addr))
        return false;
    else
        return a.getIP1()<b.getIP1();
}

IPAddr* FlowKey::getIP1() const
{
    return IP1;
}

uint16_t FlowKey::getPort1()
{
    return Port1;
}

IPAddr* FlowKey::getIP2() const
{
    return IP2;
}

uint16_t FlowKey::getPort2()
{
    return Port2;
}
