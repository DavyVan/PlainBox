#include "ipaddr.h"
#include<arpa/inet.h>
#include<memory.h>
#include<iostream>

IPAddr::IPAddr()
{
    //ctor
}

IPAddr::~IPAddr()
{
    //dtor
}

IPv4Addr::IPv4Addr()
    : ip_(0)
{

}

IPv4Addr::IPv4Addr(uint32_t ip)
    : ip_(ip)
{

}

uint8_t* IPv4Addr::getAddr_raw()
{
    return (uint8_t*)&ip_;
}

string IPv4Addr::getAddr_str()
{
    char buf[INET_ADDRSTRLEN + 1] = {0};
    inet_ntop(AF_INET, &ip_, buf, INET_ADDRSTRLEN);
    return buf;
}

ostream& operator<< (ostream& os, IPv4Addr &ip)
{
    return os << ip.getAddr_str();
}

bool operator< (const IPv4Addr &a, const IPv4Addr &b)
{
    return a.ip_ < b.ip_;
}

IPv6Addr::IPv6Addr()
{
    memset(ip_, 0, 16);
}

IPv6Addr::IPv6Addr(uint8_t* ip)
{
    memcpy(ip_, ip, 16);
}

uint8_t* IPv6Addr::getAddr_raw() const
{
    return const_cast<uint8_t*>(ip_);
}

string IPv6Addr::getAddr_str()
{
    char buf[INET6_ADDRSTRLEN + 1] = {0};
    inet_ntop(AF_INET6, &ip_, buf, INET6_ADDRSTRLEN);
    return buf;
}

ostream& operator<< (ostream& os, IPv6Addr &ip)
{
    return os << ip.getAddr_str();
}

bool operator< (const IPv6Addr &a, const IPv6Addr &b)
{
    uint8_t* a_ = a.getAddr_raw();
    uint8_t* b_ = b.getAddr_raw();
    for(int i = 0; i < 16; i++)
    {
        if(a_[i] < b_[i])
        {
            return true;
        }
        else if(a_[i] > b_[i])
        {
            return false;
        }
        else if(a_[i] == b_[i])
            continue;
    }
}

bool equalto(uint8_t* a, uint8_t *b, unsigned int length)
{
    for(int i = 0; i < length; i++)
    {
        if(a[i] != b[i])
            return false;
    }
    return true;
}
