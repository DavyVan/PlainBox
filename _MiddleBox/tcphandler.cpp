#include<memory.h>
#include "tcphandler.h"

TCPHandler::TCPHandler()
{
    current_seq[0] = 0;
    current_seq[1] = 0;
    next_seq[0] = 0;
    next_seq[1] = 0;

    temp[0] = NULL;
    temp[1] = NULL;

    applayerhandler = NULL;
}

TCPHandler::~TCPHandler()
{
    delete(applayerhandler);
}

void TCPHandler::reAssemblePacket(uint16_t srcPort, uint16_t destPort, const uint8_t *payload, unsigned int length, TCPDataDirection direction, uint32_t seq)
{
    //sequence
    if(next_seq[direction] == 0 || next_seq[direction] == seq)
    {
        current_seq[direction] = seq;
        next_seq[direction] = current_seq[direction] + length;

        //construct new TCPDataNode
        TCPDataNode *node = new TCPDataNode();
        node->length = length;
        node->seq = seq;
        node->next = NULL;
        memcpy(node->tcp_payload, payload, length);

        //check if the rest of temp is ordered.
        TCPDataNode *p = temp[direction];
        TCPDataNode *q = node;
        uint32_t p_seq = next_seq[direction];
        while(p != NULL && p->seq == p_seq)
        {
            q->next = p;
            p_seq += p->length;
            q = q->next;
            p = p->next;
        }
        q->next = NULL;
        temp[direction] = p;

        //application layer processing
        if(srcPort == 443 || destPort == 443)
        {
            applayerhandler = new TLSHandler();
            applayerhandler->parse(node, direction);
        }
    }
    else if(next_seq[direction] != seq)
    {
        //dis-ordered
        //construct TCPDataNode
        TCPDataNode *node = new TCPDataNode();
        node->length = length;
        node->seq = seq;
        node->next = NULL;
        memcpy(node->tcp_payload, payload, length);

        //insert it into temp
        TCPDataNode *q = NULL;
        TCPDataNode *p = temp[direction];
        while(p != NULL && node->seq > p->seq)
        {
            q = p;
            p = p->next;
        }
        if(q == NULL)
            temp[direction] = node;
        else
            q->next = node;
        node->next = p;
    }
}
