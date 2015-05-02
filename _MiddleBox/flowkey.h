#ifndef FLOWKEY_H
#define FLOWKEY_H

#include"ipaddr.h"

class FlowKey
{
    public:
        FlowKey();

        friend bool operator< (const FlowKey &a, const FlowKey &b);
        IPAddr* getIP1();
        IPAddr* getIP2();

        ~FlowKey();
    private:
        IPAddr IP1;
        uint16_t Port1;
        IPAddr IP2;
        uint16_t Port2;
};

#endif // FLOWKEY_H
