#ifndef TCPHANDLER_H
#define TCPHANDLER_H

#include<arpa/inet.h>
#include"tcpdatastructure.h"
#include"applayerhandler.h"




/*
* TCPHandler is aim to re-assemble TCP segment into a link list
* which is consist of FlowDataNode and its head is in FlowInfo.
* Dis-ordered segment will temperarily stay in FlowInfo's own temp link list(temp_1to2/temp_2to1).
*/
class TCPHandler
{
    public:
        TCPHandler();

        void reAssemblePacket(uint16_t srcPort, uint16_t destPort, const uint8_t *payload, unsigned int length, TCPDataDirection direction, uint32_t seq, FlowKey* flowkey);

        ~TCPHandler();
    private:
        uint32_t current_seq[2];
        uint32_t next_seq[2];
        TCPDataNode *temp[2];
        /*uint32_t current_seq_1to2;
        uint32_t next_seq_1to2;
        uint32_t current_seq_2to1;
        uint32_t next_seq_2to1;
        //dis-ordered segment will be stored here.
        TCPDataNode *temp_1to2;
        TCPDataNode *temp_2to1;
        */
        AppLayerHandler* applayerhandler;
};

#endif // TCPHANDLER_H
