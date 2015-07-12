#ifndef APPLAYERHANDLER_H
#define APPLAYERHANDLER_H

#include<arpa/inet.h>
#include<memory.h>
#include"tcpdatastructure.h"
#include"flowkey.h"
#include "abe.h"

//this might be a problem, existing a include circle.
//#include"tcphandler.h"

enum AppLayerDataDirection
{
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
    PLACEHOLDER
};

class AppLayerHandler
{
    public:
        AppLayerHandler();
        virtual void* parse(TCPDataNode *head, TCPDataDirection direction, FlowKey* flowkey) = 0;
        virtual void process(void *record, TCPDataDirection direction, FlowKey* flowkey) = 0;
        virtual ~AppLayerHandler() = 0;
        virtual int handleKeys(const uint8_t *payload, unsigned int length) {}
        
        ABEFile abe;
    private:
};



#endif // APPLAYERHANDLER_H
