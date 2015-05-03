#include "ipaddr.h"
#include<arpa/inet.h>

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
    return &ip_;
}

char* IPv4Addr::getAddr_str()
{
    char buf[INET_ADDRSTRLEN + 1] = {0};
    inet_ntop(AF_INET, &ip_, buf, INET_ADDRSTRLEN);
    return buf;
}

ostream& operator<< (ostream& os, const IPv4Addr &ip)
{
    return os << ip.getAddr_str();
}

IPv6Addr::IPv6Addr()
{
    memset(ip_, 0, 16);
}

IPv6Addr::IPv6Addr(uint8_t* ip)
{
    memcpy(ip_, ip, 16);
}

uint8_t* IPv6Addr::getAddr_raw()
{
    return ip_;
}

char* IPv6Addr::getAddr_str()
{
    char buf[INET6_ADDRSTRLEN + 1] = {0};
    inet_ntop(AF_INET6, &ip_, buf, INET6_ADDRSTRLEN);
    return buf;
}


ostream& operator<< (ostream& os, const IPv6Addr &ip)
{
    return os << ip.getAddr_str();
}
