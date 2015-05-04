/*
*This file provide some proper functions to get properties of IPv4 header.
*/
#ifndef IP4HDR_H
#define IP4HDR_H

#include<netinet/ip.h>
#include<string>
using namespace std;

class IP4Hdr
{
    public:
        IP4Hdr(const uint8_t* const input);

        unsigned int getHL();   //bytes

        uint32_t getSrcIP();
        string getSrcIPstr();
        uint32_t getDestIP();
        string getDestIPstr();

        uint16_t getTotalLen();

        uint8_t getProtocol();

        ~IP4Hdr();
    private:
        iphdr header;
};

#endif // IP4HDR_H
