#ifndef FLOWKEY_H
#define FLOWKEY_H

#include"ipaddr.h"

class FlowKey
{
    public:
        FlowKey(IPAddr *ip1, uint16_t port1, IPAddr *ip2, uint16_t port2);

        friend bool operator< (const FlowKey &a, const FlowKey &b);
        IPAddr* getIP1() const;
        uint16_t getPort1() const;
        IPAddr* getIP2() const;
        uint16_t getPort2() const;
        unsigned long map_key_gen();

        ~FlowKey();
    private:
        IPAddr *IP1;
        uint16_t Port1;
        IPAddr *IP2;
        uint16_t Port2;
};

#endif // FLOWKEY_H
