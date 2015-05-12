#ifndef APPLAYERHANDLER_H
#define APPLAYERHANDLER_H

#include<arpa/inet.h>
#include"tcpdatastructure.h"

//this might be a problem, existing a include circle.
//#include"tcphandler.h"

class AppLayerHandler
{
    public:
        AppLayerHandler();
        virtual void* parse(TCPDataNode *head, TCPDataDirection direction) = 0;
        virtual void process(void *record) = 0;
        virtual ~AppLayerHandler() = 0;
    private:
};

struct TLSRec
{
    uint8_t content_type;
    uint16_t version;   //byte order problem
    unsigned int length;
    uint8_t tls_payload[70000];
};

//More status to be added/modified
enum TLSStatus
{
    INITIAL,
    HANDSHAKE_CLIENTHELLO,
    HANDSHAKE_SERVERHELLO,
    HANDSHAKE_NEGOTIATING,
    WORKING
};

class TLSHandler: public AppLayerHandler
{
    public:
        TLSHandler();
        virtual void* parse(TCPDataNode* head, TCPDataDirection direction);
        virtual void process(void *record);
        void changeStatus(TLSStatus newStatus);
        TLSStatus getStatus();
        ~TLSHandler();
    private:
        uint8_t temp[2][70000];
        unsigned int temp_length[2];
        TLSStatus status;
};

#endif // APPLAYERHANDLER_H
