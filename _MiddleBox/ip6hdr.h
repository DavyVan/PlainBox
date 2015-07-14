#ifndef IP6HDR_H
#define IP6HDR_H

#include<netinet/ip6.h>

class IP6Hdr
{
    public:
        IP6Hdr(const uint8_t* const input);

        void getSrcIP(uint8_t* destArray);
        void getDestIP(uint8_t* destArray);

        uint16_t getPayloadLen();
        uint8_t getNextHeader();

        virtual ~IP6Hdr();
    private:
        ip6_hdr header;
};

#endif // IP6HDR_H
