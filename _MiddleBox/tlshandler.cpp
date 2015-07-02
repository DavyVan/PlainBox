#include<memory.h>
#include<cstdio>
#include<iostream>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include <openssl/aes.h>

#include"tlshandler.h"
#include "tls.h"
using namespace std;

TLSHandler::TLSHandler()
{
    memset(temp, 0, 70000*2);
    memset(temp_length, 0, 2);
    status = INITIAL;
    client_random = NULL;
    server_random = NULL;
    cipher_suite = 0;

    clientIs = 0;

    key_ready = false;
}

TLSHandler::~TLSHandler()
{
    if(client_random != NULL)
        delete(client_random);
    if(server_random != NULL)
        delete(server_random);
}

void* TLSHandler::parse(TCPDataNode* head, TCPDataDirection direction, FlowKey* flowkey)
{
    while(head != NULL)     //pick a TCP payload
    {
        //cout<<"TCP packet sequence is: "<<head->seq<<endl;
        unsigned int tcp_length = head->length;
        unsigned int offset = 0;
        if(temp_length[direction] == 0)
        {
            //nothing in cache
            while(tcp_length > 0)
            {
                //inspect TLS header
                uint8_t content_type = 0;
                uint16_t version = 0;
                uint16_t length = 0;
                memcpy(&content_type, head->tcp_payload + offset, 1);
                memcpy(&version, head->tcp_payload + offset +1, 2);
                version = ntohs(version);
                memcpy(&length, head->tcp_payload + offset +3, 2);
                length = ntohs(length);

                //Check if there is a completed TLS record in this TCP payload
                if(length+5 <= tcp_length)
                {
                    TLSRec rec;     //NOTICE: this instance will be destructured out of this scope.
                    memset(rec.tls_payload, 0, 70000);
                    rec.content_type = content_type;
                    rec.version = version;
                    rec.length = length;
                    memcpy(rec.tls_payload, head->tcp_payload + offset +5, length);
                    //Process the new TLS record
                    process(&rec, direction, flowkey);

                    tcp_length -= 5+length;
                    offset += 5+length;
                }
                else
                {
                    memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                    temp_length[direction] = tcp_length;
                    //cout<<"No completed TLS record in this TCP payload, put it in cache, and temp_length:"<<temp_length[direction]<<endl;

                    tcp_length = 0;     //end the loop, continue to next tcp payload
                }
            }
        }
        else
        {
            //it has imcompleted TLSRec in cache.
            //inspect TLS header that stored in cache.
            uint8_t content_type = 0;
            uint16_t version = 0;
            uint16_t length = 0;
            memcpy(&content_type, temp[direction], 1);
            memcpy(&version, temp[direction] +1, 2);
            version = ntohs(version);
            memcpy(&length, temp[direction] +3, 2);
            length = ntohs(length);

            //Check if there is a completed TLS record including current TCP payload.
            if(length+5 <= temp_length[direction]+tcp_length)
            {
                //it can be a completed TLS record
                TLSRec rec;
                rec.content_type = content_type;
                rec.version = version;
                rec.length = length;
                memcpy(rec.tls_payload, temp[direction]+5, temp_length[direction]-5);
                memcpy(rec.tls_payload+temp_length[direction]-5, head->tcp_payload, length-temp_length[direction]+5);
                tcp_length -= length-temp_length[direction]+5;
                offset += length-temp_length[direction]+5;
                temp_length[direction] = 0;

                //processing TLS record
                process(&rec, direction, flowkey);

                while(tcp_length > 0)
                {
                    //inspect TLS header
                    uint8_t content_type = 0;
                    uint16_t version = 0;
                    uint16_t length = 0;
                    memcpy(&content_type, head->tcp_payload + offset, 1);
                    memcpy(&version, head->tcp_payload + offset +1, 2);
                    version = ntohs(version);
                    memcpy(&length, head->tcp_payload + offset +3, 2);
                    length = ntohs(length);

                    //Check if there is a completed TLS record in this TCP payload
                    if(length+5 <= tcp_length)
                    {
                        TLSRec rec;
                        rec.content_type = content_type;
                        rec.version = version;
                        rec.length = length;
                        memcpy(rec.tls_payload, head->tcp_payload + offset +5, length);
                        //Process the new TLS record
                        process(&rec, direction, flowkey);

                        tcp_length -= 5+length;
                        offset += 5+length;
                    }
                    else
                    {
                        //TODO: No completed TLS record in this TCP payload, put it in cache
                        memcpy(temp[direction], head->tcp_payload + offset, tcp_length);
                        temp_length[direction] = tcp_length;

                        tcp_length = 0;     //end the loop, continue to next tcp payload
                    }
                }
            }
            else
            {
                //still not a completed TLS record, put current TCP payload into cache.
                memcpy(temp[direction]+temp_length[direction], head->tcp_payload, tcp_length);
                temp_length[direction] += tcp_length;
            }
        }
        //delete and move head on
        TCPDataNode *p = head->next;
        head->next = NULL;
        delete(head);
        head = p;
    }
}

void TLSHandler::process(void *record, TCPDataDirection direction, FlowKey* flowkey)
{
    TLSRec *rec = (TLSRec*) record;

    switch(rec->version)
    {
        case 0x0303:
            cout<<"TLS v1.2 ";
            break;
        case 0x0301:
            cout<<"TLS v1.0 ";
            break;
        default:
            cout<<"TLS v"<<hex<<rec->version<<dec<<" ";
            break;
    }

    if(rec->content_type == 20)
    {
        cout<<"CHANGE_CIPHER_SPEC"<<endl;
    }
    else if(rec->content_type == 21)
    {
        cout<<"ALERT"<<endl;
    }
    else if(rec->content_type == 22)
    {
        cout<<"HANDSHAKE - ";
        uint8_t handShakeType = 255;
        uint32_t length = 0;    //HandShakeType & length
        memcpy(&length, rec->tls_payload, 4);
        length = ntohl(length);
        //printf("%4x\n", length);
        if((length & 0xff000000) == 0x01000000)   //client hello
        {
            //length = length & 0x00ffffff;
            cout<<"Client Hello\n";

            //set clientIs
            if(clientIs == 0)
            {
                if(direction == _1to2)
                    clientIs = 1;
                else if(direction == _2to1)
                    clientIs = 2;
            }

            uint8_t cr[32] = {0};
            memcpy(cr, rec->tls_payload+6, 32);
            setClientRandom(cr);
            cout<<"client random is: ";
            for(int i = 0; i < 32; i++)
                printf("%02x", cr[i]);
            printf("\n");

            //getTLSKey
            if(client_random && server_random && cipher_suite != 0)
            {
                getTLSKey(client_random, server_random, cipher_suite, flowkey, direction);
            }
        }
        else if((length & 0xff000000) == 0x02000000)  //server hello
        {
            //length = length & 0x00ffffff;
            cout<<"Server Hello\n";

            //set clientIs
            if(clientIs == 0)
            {
                if(direction == _1to2)
                    clientIs = 2;
                else if(direction == _2to1)
                    clientIs = 1;
            }

            uint8_t sr[32] = {0};
            memcpy(sr, rec->tls_payload+6, 32);
            setServerRandom(sr);
            cout<<"server random is: ";
            for(int i = 0; i < 32; i++)
                printf("%02x", sr[i]);
            printf("\n");
            uint8_t session_id_len = 0;
            memcpy(&session_id_len, rec->tls_payload+4+6+28, 1);
            uint16_t cs = 0;
            memcpy(&cs, rec->tls_payload+4+6+28+1+session_id_len, 2);
            cs = ntohs(cs);
            setCipherSuite(cs);
            printf("cipher_suite is: %02x\n", cs);

            //getTLSKey
            if(client_random && server_random && cipher_suite != 0)
            {
                getTLSKey(client_random, server_random, cipher_suite, flowkey, direction);
            }
        }
        else
        {
            //printf("%04x\n", length & 0xff000000);
            cout<<"Encrypted Handshake Record\n";
        }
    }
    else if(rec->content_type == 23)
    {
        //cout<<"APPLICATION_DATA "<<rec->length<<" bytes"<<endl;
        if(/*TODO: if key exists*/1)
        {
            decrypt(cipher_suite, NULL, rec, getAppLayerDataDirection(direction));  // You can get correct direction like this
        }
    }
    else
    {
        cout<<"Unknown Content Type"<<endl;
    }
    //TLS record is no need to delete.
}

uint8_t* TLSHandler::getTLSKey(uint8_t* cr, uint8_t* sr, uint16_t cs, FlowKey* flowkey, TCPDataDirection direction)
{
    cout<<"getTLSKey() is called!\n";
/*    cout<<"@param cr is client_random\n";
    cout<<"@param sr is server_random\n";
    cout<<"@param cs is cipher_suite\n";
    cout<<"@param flowinfo is replaced by flowkey, because .h file circle\n";
    cout<<"@param direction indicates the data flow direction\n";*/
    cout<<"flowkey is printed below:\n";
    flowkey->print(direction);

    if (!key_ready && cipher_suite == 0x002f) {//Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
        uint8_t* ms = (uint8_t*)getMasterSecret((char*)cr);
        if (ms) {
            cout << "@@ succ getms\n";
            cout << "Begin calc key!" << endl;
            char curch = 'A';
            int curchcnt = 1;
            unsigned char buf[1000];
            unsigned char buf2[1000];
            memcpy(buf2, ms, 48);
            unsigned char key_block[1000];
            int kbsize = 0;
            while (kbsize < 40 + 32 + 32) {

                int pos = 0;
                for (int i = 0; i < curchcnt; ++i)
                    buf[pos++] = curch;
                curchcnt++;
                curch++;
                memcpy(buf + pos, ms, 48);
                pos += 48;
                memcpy(buf + pos, sr, 32);
                pos += 32;
                memcpy(buf + pos, cr, 32);
                pos += 32;
                SHA1(buf, pos, buf2 + 48);
                MD5(buf2, 48 + 20, key_block + kbsize);
                kbsize += 16;
            }
            printf("@@ kbsize=%d ch=%c\n", kbsize, curch-1);

            km.client_write_key_len = 16;
            memcpy(km.client_write_key, key_block + 20 + 20, 16);
            km.server_write_key_len = 16;
            memcpy(km.server_write_key, key_block + 20 + 20 + 16, 16);
            km.client_write_iv_len = 16;
            memcpy(km.client_write_iv, key_block + 20 + 20 + 16 + 16, 16);
            km.server_write_iv_len = 16;
            memcpy(km.server_write_iv, key_block + 20 + 20 + 16 + 16 + 16, 16);

            key_ready = true;
        } else {
                cout << "@@ fail getms\n";
        }
    }

    return NULL;
}

void TLSHandler::decrypt(uint16_t cs, uint8_t* key, TLSRec* record, AppLayerDataDirection direction)
{
    /// You can use like this:
    /// if(direction == CLIENT_TO_SERVER)
    ///     cout<<"decrypt() is called! CLIENT_TO_SERVER\n";
    /// else if(direction == SERVER_TO_CLIENT)
    ///     cout<<"decrypt() is called! SERVER_TO_CLIENT\n";

    if (key_ready && direction == _1to2) {
        cout<<"decrypt() is called!\n";
/*    cout<<"@param cs is cipher_suite\n";
    cout<<"@param key is TLS key which is from getTLSKey()\n";
    cout<<"@param record is TLSRec that is waiting for decrypted\n";*/
        cout<<"APPLICATION_DATA "<<record->length<<" bytes"<<endl;
        printf("%x\n", record->length);
        unsigned char dec_out[123450];
        AES_KEY dec_key;
        AES_set_decrypt_key(km.client_write_key, 128, &dec_key); // Size of key is in bits
	    AES_cbc_encrypt(record->tls_payload, dec_out, record->length, &dec_key, km.client_write_iv, AES_DECRYPT);
	    cout << "succ???"<<endl;
	    for (int i = 0; i < 20 && i < record->length; ++i) putchar(dec_out[i]);

    }

}

AppLayerDataDirection TLSHandler::getAppLayerDataDirection(TCPDataDirection tcpdirection)
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
