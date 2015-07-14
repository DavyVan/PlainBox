#ifndef UDPHDR_H
#define UDPHDR_H

#include<netinet/udp.h>
#include<netinet/in.h>

class UDPHdr
{
    public:
        UDPHdr(const uint8_t* input);

        uint16_t getSrcPort();
        uint16_t getDestPort();
        uint16_t getLength();

        virtual ~UDPHdr();
    private:
        udphdr header;
};

#endif // UDPHDR_H
