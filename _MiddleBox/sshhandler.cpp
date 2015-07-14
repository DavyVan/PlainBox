#include<memory.h>
#include<iostream>
#include<cstring>
#include<cstdio>
#include<openssl/aes.h>
#include<sys/time.h>
#include "sshhandler.h"
#include"abe.h"
using namespace std;

extern int hexToBinDigit(char ch);
extern int hexToBin(char *src, char *dst);

SSHHandler::SSHHandler()
{
    memset(temp, 0, 70000*2);
    memset(temp_length, 0, 2);
    status = SSH_INITIAL;
    clientIs = 0;
    mac_length[0] = mac_length[1] = 0;
    isEncrypted[0] = isEncrypted[1] = false;
    km = NULL;
}

SSHHandler::~SSHHandler()
{
    if(km)
        delete(km);
}

void* SSHHandler::parse(TCPDataNode *head, TCPDataDirection direction, FlowKey* flowkey)
{
    while(head != NULL)
    {
        /* If packet has been encrypted, copy all of SSH content to SSRec.ssh_payload_padding_mac. It will be handled in process().
         * packet_length is the total length of SSH content.
         */
        if(isEncrypted[direction])
        {
            SSHRec rec;
            memset(rec.ssh_payload_padding_mac, 0, 70000);
            rec.packet_length = head->length;
            rec.padding_length = 0;
            memcpy(rec.ssh_payload_padding_mac, head->tcp_payload, head->length);
            process(&rec, direction, flowkey);

            //delete current TCPDataNode and move ahead
            TCPDataNode *p = head->next;
            head->next = NULL;
            delete(head);
            head = p;

            continue;
        }

        unsigned int tcp_length = head->length;
        unsigned int offset = 0;

        if(temp_length[direction] == 0)     //nothing in cache
        {
            while(tcp_length > 0)   //start parse SSH record
            {
                //SSH header
                uint32_t packet_length = 0;
                uint8_t padding_length = 0;
                uint32_t total_length = 0;      //including packet_length, padding_length, payload, padding data, MAC(namely, all of SSH data)
                memcpy(&packet_length, head->tcp_payload + offset, 4);
                packet_length = ntohl(packet_length);
                memcpy(&padding_length, head->tcp_payload + offset + 4, 1);

                //handle the Protocol Version Exchange string
                if(packet_length == 0x5353482d && *(head->tcp_payload+tcp_length-2) == 0x0d && *(head->tcp_payload+tcp_length-1) == 0x0a)
                {
                    cout<<"Protocol Version Exchange: ";
                    for(int i = 0; i < tcp_length-2; i++)   //skip \r\n
                        cout<<(char)head->tcp_payload[i];
                    cout<<endl;
                    break;  //Protocol Version Exchange is always alone.
                }
                printf("packet_length:%04x\n", packet_length);

                //calculate total_length
                total_length = packet_length + 4;
                if(isEncrypted[direction])
                    total_length += mac_length[direction];

                //Check if there is a completed SSH record in this TCP payload.
                if(total_length <= tcp_length)
                {
                    SSHRec rec;
                    memset(rec.ssh_payload_padding_mac, 0, 70000);
                    //memset(rec.mac, 0, 200);
                    rec.packet_length = packet_length;
                    rec.padding_length = padding_length;
                    memcpy(rec.ssh_payload_padding_mac, head->tcp_payload + offset + 5, total_length-5);

                    process(&rec, direction, flowkey);

                    tcp_length -= total_length;
                    offset += total_length;
                }
                else    //No completed SSH record in this TCP payload, cache it.
                {
                    memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                    temp_length[direction] = tcp_length;
                    cout<<"No completed SSH record in this TCP payload, put it in cache, and temp_length:"<<temp_length[direction]<<endl;

                    tcp_length = 0;
                }
            }
        }
        else    //it has imcompleted SSH record in cache.
        {
            uint32_t packet_length = 0;
            uint8_t padding_length = 0;
            uint32_t total_length = 0;
            memcpy(&packet_length, temp[direction], 4);
            packet_length = ntohl(packet_length);
            memcpy(&padding_length, temp[direction] + 4, 1);

            //calculate total_length
            total_length = packet_length + 4;
            if(isEncrypted[direction])
                total_length += mac_length[direction];

            //Check there is a completed TLS record including current TCP payload and cache.
            if(total_length <= temp_length[direction] + tcp_length)     //it can be a completed SSH record.
            {
                SSHRec rec;
                rec.packet_length = packet_length;
                rec.padding_length = padding_length;
                memcpy(rec.ssh_payload_padding_mac, temp[direction] + 5, temp_length[direction]-5);
                memcpy(rec.ssh_payload_padding_mac+temp_length[direction]-5, head->tcp_payload, total_length-temp_length[direction]);
                tcp_length -= total_length-temp_length[direction];
                offset += total_length-temp_length[direction];
                temp_length[direction] = 0;

                process(&rec, direction, flowkey);

                while(tcp_length > 0)   //start parse SSH record
                {
                    //SSH header
                    uint32_t packet_length = 0;
                    uint8_t padding_length = 0;
                    uint32_t total_length = 0;      //including packet_length, padding_length, payload, padding data, MAC(namely, all of SSH data)
                    memcpy(&packet_length, head->tcp_payload + offset, 4);
                    packet_length = ntohl(packet_length);
                    memcpy(&padding_length, head->tcp_payload + offset + 4, 1);

                    //calculate total_length
                    total_length = packet_length + 4;
                    if(isEncrypted[direction])
                        total_length += mac_length[direction];

                    //Check if there is a completed SSH record in this TCP payload.
                    if(total_length <= tcp_length)
                    {
                        SSHRec rec;
                        memset(rec.ssh_payload_padding_mac, 0, 70000);
                        //memset(rec.mac, 0, 200);
                        rec.packet_length = packet_length;
                        rec.padding_length = padding_length;
                        memcpy(rec.ssh_payload_padding_mac, head->tcp_payload + offset + 5, total_length-5);

                        process(&rec, direction, flowkey);

                        tcp_length -= total_length;
                        offset += total_length;
                    }
                    else    //No completed SSH record in this TCP payload, cache it.
                    {
                        memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                        temp_length[direction] = tcp_length;
                        cout<<"No completed SSH record in this TCP payload, put it in cache, and temp_length:"<<temp_length[direction]<<endl;

                        tcp_length = 0;
                    }
                }
            }
            else    //still not a completed SSH record, put current TCP payload into cache as well.
            {
                memcpy(temp[direction]+temp_length[direction], head->tcp_payload, tcp_length);
                temp_length[direction] += tcp_length;
            }
        }
        //delete current TCPDataNode and move ahead
        TCPDataNode *p = head->next;
        head->next = NULL;
        delete(head);
        head = p;
    }
}

void SSHHandler::process(void *record, TCPDataDirection direction, FlowKey* flowkey)
{
    SSHRec *rec = (SSHRec*) record;

    //check if it needs to be decrypted.
    uint32_t packet_length;
    uint8_t padding_length;
    uint32_t payload_length;
    uint8_t ssh_payload_cipher[70000] = {0};
    uint8_t ssh_payload_plain[70000] = {0};
    uint8_t ssh_mac[200] = {0};

    if(isEncrypted[direction])
    {
        //copy mac and cipher text into local array.
        memcpy(ssh_mac, rec->ssh_payload_padding_mac + rec->packet_length - mac_length[direction], mac_length[direction]);
        memcpy(ssh_payload_cipher, rec->ssh_payload_padding_mac, rec->packet_length - mac_length[direction]);

        //prepare keys
        if(!km)
            getKeys(flowkey);

        cout<<"-------------------------before decrypt-------------------------\n";
        decrypt(rec->packet_length - mac_length[direction], ssh_payload_cipher, km, getAppLayerDataDirection(direction), &packet_length, &padding_length, ssh_payload_plain);

        payload_length = packet_length - padding_length - 1;
    }
    else    //no need to decrypt
    {
        packet_length = rec->packet_length;
        padding_length = rec->padding_length;
        payload_length = packet_length-padding_length-1;
        memcpy(ssh_payload_plain, rec->ssh_payload_padding_mac, packet_length-padding_length-1);
        //No MAC
    }

    uint8_t message_code;
    memcpy(&message_code, ssh_payload_plain, 1);
    if(message_code == 1)
        cout<<"SSH_MSG_DISCONNECT\n";
    else if(message_code == 5)
        cout<<"SSH_MSG_SERVICE_REQUEST\n";
    else if(message_code == 6)
        cout<<"SSH_MSG_SERVICE_ACCEPT\n";
    else if(message_code == 20)
    {
        cout<<"Key Exchange Init\n";
    }
    else if(message_code == 21)
    {
        cout<<"New Keys\n";
        isEncrypted[direction] = true;
        mac_length[direction] = 16;     //I assume that mac is 16 bytes long
        changeStatus(SSH_USER_AUTHENTICATION_PROTOCOL);
    }
    else if(message_code == 30)
    {
        cout<<"Diffie-Hellman Key Exchange Init\n";
        clientIs = direction == _1to2 ? 1 : 2;
    }
    else if(message_code == 31)
    {
        cout<<"Diffie-Hellman Key Exchange Reply\n";
    }
    else if(message_code == 50)
        cout<<"SSH_MSG_USERAUTH_REQUEST\n";
    else if(message_code == 51)
        cout<<"SSH_MSG_USERAUTH_FAILURE\n";
    else if(message_code == 52)
        cout<<"SSH_MSG_USERAUTH_SUCCESS\n";
    else if(message_code == 90)
        cout<<"SSH_MSG_CHANNEL_OPEN\n";
    else if(message_code == 91)
        cout<<"SSH_MSG_CHANNEL_OPEN_CONFIRMATION\n";
    else if(message_code == 93)
        cout<<"SSH_MSG_CHANNEL_WINDOW_ADJUST\n";
    else if(message_code == 94)
        cout<<"SSH_MSG_CHANNEL_DATA\n";
    else if(message_code == 96)
        cout<<"SSH_MSG_CHANNEL_EOF\n";
    else if(message_code == 97)
        cout<<"SSH_MSG_CHANNEL_CLOSE\n";
    else if(message_code == 98)
        cout<<"SSH_MSG_CHANNEL_REQUEST\n";
    else
        cout<<"Unknown Message Code: "<<(int)message_code<<endl;

    //print plain text
    cout<<"plain text in hexadecimal:\n";
    for(int i = 0; i < payload_length; i++)
        printf("%0x", ssh_payload_plain[i]);
    cout<<endl;
    cout<<"plain text in char:\n";
    for(int i = 0; i < payload_length; i++)
        printf("%c", ssh_payload_plain[i]);
    cout<<endl;
}

static long long gettime(struct timeval t1, struct timeval t2)
{
    return (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
}

void SSHHandler::getKeys(FlowKey *flowkey)
{
    char remote_ipaddr[50] = {0};
    if(clientIs == 1)
        //remote_ipaddr = flowkey->getIP2()->getAddr_str().c_str();
        //DO NOT use like this, c_str() return a *temporary* pointer to the string.
        memcpy(remote_ipaddr, flowkey->getIP2()->getAddr_str().c_str(), strlen(flowkey->getIP2()->getAddr_str().c_str()));
    else if(clientIs == 2)
        //remote_ipaddr = flowkey->getIP1()->getAddr_str().c_str();
        memcpy(remote_ipaddr, flowkey->getIP1()->getAddr_str().c_str(), strlen(flowkey->getIP1()->getAddr_str().c_str()));

    cout<<"------------------------get keys---------------------------\n";
    const char *filepath = "/etc/ssh.key";
    FILE *file = fopen(filepath, "r");
    if(!file)
    {
        cout<<"/etc/ssh.key couldn't be opened!\n";
        return;
    }
    char buf[1000];
    KeyMaterial_SSH *newkm = NULL;
    while(fgets(buf, 999, file))
    {
        char _remote_ipaddr[100] = {0};
        char _enc_alg_ctos[50] = {0};
        unsigned int _enc_key_len_ctos;
        char _enc_key_ctos[100] = {0};
        unsigned int _enc_iv_len_ctos;
        char _enc_iv_ctos[100] = {0};

        char _enc_alg_stoc[50] = {0};
        unsigned int _enc_key_len_stoc;
        char _enc_key_stoc[100] = {0};
        unsigned int _enc_iv_len_stoc;
        char _enc_iv_stoc[100] = {0};

        sscanf(buf, "%s %s %u %s %u %s %s %u %s %u %s\n",
            _remote_ipaddr,
            _enc_alg_ctos,
            &_enc_key_len_ctos,
            _enc_key_ctos,
            &_enc_iv_len_ctos,
            _enc_iv_ctos,
            _enc_alg_stoc,
            &_enc_key_len_stoc,
            _enc_key_stoc,
            &_enc_iv_len_stoc,
            _enc_iv_stoc);

//        printf("%s %s %u %s %u %s %s %u %s %u %s\n",
//            _remote_ipaddr,
//            _enc_alg_ctos,
//            _enc_key_len_ctos,
//            _enc_key_ctos,
//            _enc_iv_len_ctos,
//            _enc_iv_ctos,
//            _enc_alg_stoc,
//            _enc_key_len_stoc,
//            _enc_key_stoc,
//            _enc_iv_len_stoc,
//            _enc_iv_stoc);


        if(strcmp(remote_ipaddr, _remote_ipaddr) == 0)      //If remote_ipaddr matches this line
        {
            cout<<"Line Matched\n"<<remote_ipaddr<<endl;
            if(newkm)
                delete(newkm);
            newkm = new KeyMaterial_SSH();

            memcpy(newkm->enc_alg_ctos, _enc_alg_ctos, 50);

            newkm->enc_key_len_ctos = _enc_key_len_ctos;
            if(hexToBin(_enc_key_ctos, (char *)newkm->enc_key_ctos) != _enc_key_len_ctos)
                cout<<"enc_key_ctos hexToBin failed\n";

            newkm->enc_iv_len_ctos = _enc_iv_len_ctos;
            if(hexToBin(_enc_iv_ctos, (char *)newkm->enc_iv_ctos) != _enc_iv_len_ctos)
                cout<<"enc_iv_ctos hexToBin failed\n";

            memcpy(newkm->enc_alg_stoc, _enc_alg_stoc, 50);

            newkm->enc_key_len_stoc = _enc_key_len_stoc;
            if(hexToBin(_enc_key_stoc, (char *)newkm->enc_key_stoc) != _enc_key_len_stoc)
                cout<<"enc_key_stoc hexToBin failed\n";

            newkm->enc_iv_len_stoc = _enc_iv_len_stoc;
            if(hexToBin(_enc_iv_stoc, (char *)newkm->enc_iv_stoc) != _enc_iv_len_stoc)
                cout<<"enc_iv_stoc hexToBin failed\n";


            //ABE
            int keys_len = _enc_key_len_ctos + _enc_iv_len_ctos + _enc_key_len_stoc + _enc_iv_len_stoc;
            uint8_t keys[1000];
            memcpy(keys, newkm->enc_key_ctos, _enc_key_len_ctos);
            memcpy(keys + _enc_key_len_ctos, newkm->enc_iv_ctos, _enc_iv_len_ctos);
            memcpy(keys + _enc_key_len_ctos + _enc_iv_len_ctos, newkm->enc_key_stoc, _enc_key_len_stoc);
            memcpy(keys + _enc_key_len_ctos + _enc_iv_len_ctos + _enc_key_len_stoc, newkm->enc_iv_stoc, _enc_iv_len_stoc);
            printf("~~~~~~~~~~~~~~~keys_len=%d\n", keys_len);
            struct timeval t1;
            gettimeofday(&t1, NULL);
            ABEFile abe = abe_encrypt(keys, keys_len, "CN and (TLS)");
            struct timeval t2;
            gettimeofday(&t2, NULL);
            printf("ABE-encrypt:total time=%lld\n", gettime(t1, t2));
            struct timeval t3;
            gettimeofday(&t3, NULL);
            ABEFile abe2 = abe_decrypt(abe.f);
            struct timeval t4;
            gettimeofday(&t4, NULL);
            printf("ABE-decrypt:total time=%lld\n", gettime(t3, t4));
        }
        else
        {
            cout<<"line not matched "<<remote_ipaddr<<endl;
        }
    }
    if(newkm)
        km = newkm;
    else
        cout<<"getKey failed\n";
}

void SSHHandler::decrypt(unsigned int length, const uint8_t *payload, KeyMaterial_SSH *km, AppLayerDataDirection direction, uint32_t *packet_length, uint8_t *padding_length,uint8_t *dest)
{
    if(!km)
    {
        cout<<"NO Key Material available\n";
        return;
    }
    cout<<"---------------------------starting decrypt-----------------------------\n";
    printf(direction == CLIENT_TO_SERVER ? "client_to_server\n" : "server_to_client\n");
    char *enc_alg_name = direction == CLIENT_TO_SERVER ? km->enc_alg_ctos : km->enc_alg_stoc;
    if(strcmp(enc_alg_name, "aes128-cbc") == 0)
    {

        uint8_t out[70000] = {0};
        AES_KEY aes_key;
        AES_set_decrypt_key(direction == CLIENT_TO_SERVER ? km->enc_key_ctos : km->enc_key_stoc,
            (direction == CLIENT_TO_SERVER ? km->enc_key_len_ctos : km->enc_key_len_stoc)*8,
            &aes_key);
        //uint8_t ecount_buf[AES_BLOCK_SIZE] = {0};
        //unsigned int num = 0;

        //AES_ctr128_encrypt(payload, out, length, &aes_key, direction == CLIENT_TO_SERVER ? km->enc_iv_ctos : km->enc_iv_stoc, ecount_buf, &num);
        AES_cbc_encrypt(payload, out, length, &aes_key, direction == CLIENT_TO_SERVER ? km->enc_iv_ctos : km->enc_iv_stoc, AES_DECRYPT);

        memcpy(packet_length, out, 4);
        *packet_length = ntohl(*packet_length);
        memcpy(padding_length, out + 4, 1);
        //cout<<"cipher length: "<<length<<endl;
        cout<<"packet_length: "<<*packet_length<<" padding_length: "<<(int)*padding_length<<endl;
        memcpy(dest, out + 5, *packet_length - *padding_length - 1);
    }
    cout<<"---------------------------ending decrypt-----------------------------\n";
}

AppLayerDataDirection SSHHandler::getAppLayerDataDirection(TCPDataDirection tcpdirection)
{
    if(clientIs == 0)
        return PLACEHOLDER;
    else if(clientIs == 1)
    {
        if(tcpdirection == _1to2)
            return CLIENT_TO_SERVER;
        else if(tcpdirection == _2to1)
            return SERVER_TO_CLIENT;
    }
    else if(clientIs == 2)
    {
        if(tcpdirection == _1to2)
            return SERVER_TO_CLIENT;
        else if(tcpdirection == _2to1)
            return CLIENT_TO_SERVER;
    }
}
