#ifndef TCPHANDLER_H
#define TCPHANDLER_H

/*
* TCPHandler is aim to re-assemble TCP segment into a link list
* which is consist of FlowDataNode and its head is in FlowInfo.
* Dis-ordered segment will temperarily stay in FlowInfo's own temp link list(temp_1to2/temp_2to1).
*/
class TCPHandler
{
    public:
        TCPHandler();

        //Maybe static
        void newPacket(FlowInfo flowinfo, uint8_t *payload);

        ~TCPHandler();
    private:

};

#endif // TCPHANDLER_H
