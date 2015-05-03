#ifndef TCPHDR_H
#define TCPHDR_H

#include<netinet/tcp.h>
#include<arpa/inet.h>


class TCPHdr
{
    public:
        TCPHdr(const uint8_t *input);

        uint16_t getSrcPort();
        uint16_t getDestPort();

        uint32_t getSeq();

        unsigned int getHL();   //bytes

        bool isSYN();
        bool isACK();
        bool isRST();
        bool isFIN();

        ~TCPHdr();
    private:
        tcphdr header;
};

#endif // TCPHDR_H
