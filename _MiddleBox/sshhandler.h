#ifndef SSHHANDLER_H
#define SSHHANDLER_H

#include"applayerhandler.h"

struct SSHRec
{
    uint32_t packet_length;
    uint8_t padding_length;     //maybe encrypted, should be concatenated with payload_padding_mac(without mac) before decrypt
    uint8_t ssh_payload_padding_mac[70000];
    //uint8_t mac[200];
};

enum SSHStatus
{
    SSH_INITIAL,
    SSH_TRANSPORT_LAYER_PROTOCOL,
    SSH_USER_AUTHENTICATION_PROTOCOL,
    SSH_CONNECTION_PROTOCOL,
    SSH_CONNECTED
};

class SSHHandler: public AppLayerHandler
{
    public:
        SSHHandler();

        virtual void* parse(TCPDataNode *head, TCPDataDirection direction, FlowKey* flowkey);
        virtual void process(void *record, TCPDataDirection direction, FlowKey* flowkey);
        void changeStatus(SSHStatus newStatus);
        SSHStatus getStatus();

        ~SSHHandler();
    protected:
    private:
        bool isEncrypted[2];
        unsigned int mac_length[2];

        uint8_t temp[2][70000];
        unsigned int temp_length[2];
        SSHStatus status;

        int clientIs;   //These should be put into AppLayerHandler
        AppLayerDataDirection getAppLayerDataDirection(TCPDataDirection tcpdirection);

        //TODO: key material or sth.
};

#endif // SSHHANDLER_H
