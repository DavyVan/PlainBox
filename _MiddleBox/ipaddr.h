#ifndef IPADDR_H
#define IPADDR_H

#include<iostream>
#include<netinet/in.h>

using namespace std;

class IPAddr
{
    public:
        IPAddr();

        virtual uint8_t* getAddr_raw()=0;
        virtual char* getAddr_str()=0;

        ~IPAddr();
    private:
};

class IPv4Addr: IPAddr
{
    public:
        IPv4Addr();
        IPv4Addr(uint32_t ip);
        virtual uint8_t* getAddr_raw();
        virtual char* getAddr_str();

        friend ostream& operator<< (ostream& os, const IPv4Addr &ip);
    private:
        uint32_t ip_;
};

class IPv6Addr: IPAddr
{
    public:
        IPv6Addr();
        IPv6Addr(uint8_t* ip);
        virtual uint8_t* getAddr_raw();
        virtual char* getAddr_str();

        friend ostream& operator<< (ostream& os, const IPv6Addr &ip);
    private:
        uint8_t ip_[16];
};

#endif // IPADDR_H
