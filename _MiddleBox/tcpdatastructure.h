struct TCPDataNode
{
    unsigned int length;
    uint32_t seq;   //seq of the first byte of this TCP segment(the same as the TCP header)
    uint8_t tcp_payload[2000];
    TCPDataNode *next;
};

enum TCPDataDirection
{
    _1to2,
    _2to1
};
