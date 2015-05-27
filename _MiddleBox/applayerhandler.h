#ifndef APPLAYERHANDLER_H
#define APPLAYERHANDLER_H

#include<arpa/inet.h>
#include<memory.h>
#include"tcpdatastructure.h"
#include"flowkey.h"

//this might be a problem, existing a include circle.
//#include"tcphandler.h"

class AppLayerHandler
{
    public:
        AppLayerHandler();
        virtual void* parse(TCPDataNode *head, TCPDataDirection direction, FlowKey* flowkey) = 0;
        virtual void process(void *record, TCPDataDirection direction, FlowKey* flowkey) = 0;
        virtual ~AppLayerHandler() = 0;
    private:
};



#endif // APPLAYERHANDLER_H
