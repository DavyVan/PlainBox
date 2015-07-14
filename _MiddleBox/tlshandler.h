#ifndef TLSHANDLER_H
#define TLSHANDLER_H

#include"applayerhandler.h"
#include "tls.h"

struct TLSRec
{
    uint8_t content_type;
    uint16_t version;   //byte order problem
    uint16_t length;
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
        virtual void* parse(TCPDataNode* head, TCPDataDirection direction, FlowKey* flowkey);
        virtual void process(void *record, TCPDataDirection direction, FlowKey* flowkey);
        void changeStatus(TLSStatus newStatus){status = newStatus;};
        TLSStatus getStatus(){return status;};

        void setClientRandom(uint8_t* cr){client_random = new uint8_t[32]; memcpy(client_random, cr, 32);};
        void setServerRandom(uint8_t* sr){server_random = new uint8_t[32]; memcpy(server_random, sr, 32);};
        void setCipherSuite(uint16_t cs){cipher_suite = cs;};
        uint8_t* getClientRandom(){return client_random;};
        uint8_t* getServerRandom(){return server_random;};
        uint16_t getCipherSuite(){return cipher_suite;};

        /// @brief get TLS key from a TCP connection between Middlebox and Client
        ///
        /// @param cr   client_random
        /// @param sr   server_random
        /// @param cs   cipher_suite
        /// @param flowkey  alternative choice of FlowInfo
        /// @param direction    data flow direction
        //TODO: return type is to be decided.
        uint8_t* getTLSKey(uint8_t* cr, uint8_t* sr, uint16_t cs, FlowKey* flowkey, TCPDataDirection direction);

        /// @brief get plaintext of a record with Application Data
        void decrypt(uint16_t cs, uint8_t* key, TLSRec* record, AppLayerDataDirection direction);
        
        virtual int handleKeys(const uint8_t *payload, unsigned int length);

        ~TLSHandler();
    private:
        uint8_t temp[2][70000];
        unsigned int temp_length[2];
        TLSStatus status;
        uint8_t* client_random;
        uint8_t* server_random;
        uint16_t cipher_suite;

        int clientIs;   //which side is client, 1 for IP1, 2 for IP2. Another idea is store this in FlowKey.
        AppLayerDataDirection getAppLayerDataDirection(TCPDataDirection tcpdirection);

        bool key_ready;//for client side
        bool key_ready_mbox;//for mbox side
        KeyMaterial km;

        int target_mac_len;        
        int target_key_len;
        int target_iv_len;

};

#endif // TLSHANDLER_H
