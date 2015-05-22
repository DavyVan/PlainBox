#ifndef APPLAYERHANDLER_H
#define APPLAYERHANDLER_H

#include<arpa/inet.h>
#include<memory.h>
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

        void setClientRandom(uint8_t* cr){client_random = new uint8_t[28]; memcpy(client_random, cr, 28);};
        void setServerRandom(uint8_t* sr){server_random = new uint8_t[28]; memcpy(server_random, sr, 28);};
        void setCipherSuite(uint16_t cs){cipher_suite = cs;};
        uint8_t* getClientRandom(){return client_random;};
        uint8_t* getServerRandom(){return server_random;};
        uint16_t getCipherSuite(){return cipher_suite;};
        ~TLSHandler();
    private:
        uint8_t temp[2][70000];
        unsigned int temp_length[2];
        TLSStatus status;
        uint8_t* client_random;
        uint8_t* server_random;
        uint16_t cipher_suite;
};

#endif // APPLAYERHANDLER_H
