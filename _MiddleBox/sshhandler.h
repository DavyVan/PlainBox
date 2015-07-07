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

struct KeyMaterial_SSH
{
    char enc_alg_ctos[50];
    unsigned int enc_key_len_ctos;
    uint8_t enc_key_ctos[100];
    unsigned int enc_iv_len_ctos;
    uint8_t enc_iv_ctos[100];

    char enc_alg_stoc[50];
    unsigned int enc_key_len_stoc;
    uint8_t enc_key_stoc[100];
    unsigned int enc_iv_len_stoc;
    uint8_t enc_iv_stoc[100];
};

class SSHHandler: public AppLayerHandler
{
    public:
        SSHHandler();

        virtual void* parse(TCPDataNode *head, TCPDataDirection direction, FlowKey* flowkey);
        virtual void process(void *record, TCPDataDirection direction, FlowKey* flowkey);
        void changeStatus(SSHStatus newStatus){status = newStatus;};
        SSHStatus getStatus(){return status;};

        //Get keys from file /etc/ssh.key and save them to km
        void getKeys(FlowKey *flowkey);
        void decrypt(unsigned int length, const uint8_t *payload, KeyMaterial_SSH *km, AppLayerDataDirection direction, uint32_t *packet_length, uint8_t *padding_length,uint8_t *dest);

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

        KeyMaterial_SSH *km;
};

#endif // SSHHANDLER_H
