#include<typeinfo>
#include<iostream>
#include "flowkey.h"
#include"ipaddr.h"

//We assume that a TCP connection only establishs upon ONE type of IP protocol
FlowKey::FlowKey(IPAddr *ip1, uint16_t port1, IPAddr *ip2, uint16_t port2)
{
    int length;
    bool smaller = false;   //if ip1 smaller than ip2
    if(typeid(*ip1) == typeid(IPv4Addr))
        length = 4;
    else if(typeid(*ip1) == typeid(IPv6Addr))
        length = 16;
    uint8_t* ip1_ = ip1->getAddr_raw();
    uint8_t* ip2_ = ip2->getAddr_raw();
    for(int i = 0; i < length; i++)
    {
        if(ip1_[i] < ip2_[i])
        {
            smaller = true;
            break;
        }
        else if(ip1_[i] > ip2_[i])
        {
            smaller = false;
            break;
        }
        else if(ip1_[i] == ip2_[i])
            continue;
    }
    if(smaller)
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

/*bool operator< (const FlowKey &a, const FlowKey &b)
{
    IPAddr* a_ = a.getIP1();
    IPAddr* b_ = b.getIP1();
    if(typeid(*a_) == typeid(IPv4Addr) && typeid(*b_) == typeid(IPv6Addr))
        return true;
    else if(typeid(*a_) == typeid(IPv6Addr) && typeid(*b_) == typeid(IPv4Addr))
        return false;
    else
    {
        int length;
        if(typeid(*a_) == typeid(IPv4Addr))
            length = 4;
        else if(typeid(*a_) == typeid(IPv6Addr))
            length = 16;
        uint8_t* a__ = a_->getAddr_raw();
        uint8_t* b__ = b_->getAddr_raw();
        for(int i = 0; i < length; i++)
        {
            if(a__[i] < b__[i])
            {
                return true;
            }
            else if(a__[i] > b__[i])
            {
                return false;
            }
            else if(a__[i] == b__[i])
                continue;
        }
        //if IP address both are same, compare the ports
        return a.getPort1() < b.getPort1();
    }
}*/

IPAddr* FlowKey::getIP1() const
{
    return IP1;
}

uint16_t FlowKey::getPort1() const
{
    return Port1;
}

IPAddr* FlowKey::getIP2() const
{
    return IP2;
}

uint16_t FlowKey::getPort2() const
{
    return Port2;
}

unsigned long FlowKey::map_key_gen()
{
    unsigned long ret = 0;
    if(typeid(*IP1) == typeid(IPv4Addr))
    {
        uint8_t* t = IP1->getAddr_raw();
        ret += t[2];
        ret <<= 8;
        ret += t[3];
        ret <<= 16;
        ret += Port1;
        ret <<= 8;
        t = IP2->getAddr_raw();
        ret += t[2];
        ret <<= 8;
        ret += t[3];
        ret <<= 16;
        ret += Port2;
        return ret;
    }
    else if(typeid(*IP1) == typeid(IPv6Addr))
    {
        uint8_t* t = IP1->getAddr_raw();
        ret += t[14];
        ret <<= 8;
        ret += t[15];
        ret <<= 16;
        ret += Port1;
        ret <<= 8;
        t = IP2->getAddr_raw();
        ret += t[14];
        ret <<= 8;
        ret += t[15];
        ret <<= 16;
        ret += Port2;
        return ret;
    }
}

void FlowKey::print(TCPDataDirection direction)
{
    if(direction == _1to2)
    {
        if(typeid(*IP1) == typeid(IPv4Addr))
        {
            cout<<*((IPv4Addr*)IP1)<<":"<<Port1<<" --> "<<*((IPv4Addr*)IP2)<<":"<<Port2<<endl;
        }
        else if(typeid(*IP1) == typeid(IPv6Addr))
        {
            cout<<*((IPv6Addr*)IP1)<<":"<<Port1<<" --> "<<*((IPv6Addr*)IP2)<<":"<<Port2<<endl;
        }
    }
    else if(direction == _2to1)
    {
        if(typeid(*IP1) == typeid(IPv4Addr))
        {
            cout<<*((IPv4Addr*)IP2)<<":"<<Port2<<" --> "<<*((IPv4Addr*)IP1)<<":"<<Port1<<endl;
        }
        else if(typeid(*IP1) == typeid(IPv6Addr))
        {
            cout<<*((IPv6Addr*)IP2)<<":"<<Port2<<" --> "<<*((IPv6Addr*)IP1)<<":"<<Port1<<endl;
        }
    }
}
