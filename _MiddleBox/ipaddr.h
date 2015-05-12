#ifndef IPADDR_H
#define IPADDR_H

#include<iostream>
#include<string>
#include<netinet/in.h>
#include<boost/shared_ptr.hpp>

using namespace std;

class IPAddr
{
    public:
        IPAddr();

        virtual uint8_t* getAddr_raw()=0;
        virtual string getAddr_str()=0;

        ~IPAddr();
    private:
};

class IPv4Addr: public IPAddr
{
    public:
        IPv4Addr();
        IPv4Addr(uint32_t ip);
        virtual uint8_t* getAddr_raw();
        virtual string getAddr_str();

        friend ostream& operator<< (ostream& os, IPv4Addr &ip);
        friend bool operator< (const IPv4Addr &a, const IPv4Addr &b);
    private:
        uint32_t ip_;
};

class IPv6Addr: public IPAddr
{
    public:
        IPv6Addr();
        IPv6Addr(uint8_t* ip);
        virtual uint8_t* getAddr_raw() const;
        virtual string getAddr_str();

        //TODO: friend operator=
        friend ostream& operator<< (ostream& os, IPv6Addr &ip);
        friend bool operator< (const IPv6Addr &a, const IPv6Addr &b);
    private:
        uint8_t ip_[16];
};

bool equalto(uint8_t* a, uint8_t *b, unsigned int length);

typedef boost::shared_ptr<IPAddr> IPAddrPtr;
typedef boost::shared_ptr<IPv4Addr> IPv4AddrPtr;
typedef boost::shared_ptr<IPv6Addr> IPv6AddrPtr;

#endif // IPADDR_H
