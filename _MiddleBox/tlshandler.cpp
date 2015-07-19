#include<memory.h>
#include<cstdio>
#include<iostream>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include <openssl/aes.h>
#include <sys/time.h>

#include"tlshandler.h"
#include "tls.h"
#include "abe.h"
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
    key_ready_mbox = false;
}

TLSHandler::~TLSHandler()
{
    if(client_random != NULL)
        delete(client_random);
    if(server_random != NULL)
        delete(server_random);
}

int SHA256(uint8_t *in1, int in1_len, uint8_t *in2, int in2_len, uint8_t *out)
{
    SHA256_CTX ctx; 
    SHA256_Init(&ctx); 
    SHA256_Update(&ctx, in1, in1_len);
    SHA256_Update(&ctx, in2, in2_len);  
    SHA256_Final(out, &ctx); 
    return SHA256_DIGEST_LENGTH;
}

int HMAC_SHA256(uint8_t *key, int key_len, uint8_t *msg, int msg_len, uint8_t *out)
{
    int blocksize = 64;//64
    uint8_t opad[64];
    uint8_t ipad[64];
    for (int i = 0; i < blocksize; ++i) {
        opad[i] = 0x5c;
        ipad[i] = 0x36;
        if (i < key_len) {
            opad[i] ^= key[i];
            ipad[i] ^= key[i];
        }
    }
    uint8_t buf[1000] = {0};
    int len = SHA256(ipad, blocksize, msg, msg_len, buf);
    //printf("HMAC_SHA256 key_len=%d msg_len=%d len=%d\n", key_len, msg_len, len);
    return SHA256(opad, blocksize, buf, len, out);
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
        cout<<"#####   CHANGE_CIPHER_SPEC"<<endl;
        if (!key_ready) {
            if(client_random && server_random && cipher_suite != 0)
            {
                getTLSKey(client_random, server_random, cipher_suite, flowkey, direction);
            }
        }
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
            cout<<"#####   Client Hello\n";

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
            cout<<"#####   Server Hello\n";

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
            switch (cs) {
            case 0xc014:
                target_mac_len = 20;
                target_key_len = 32;
                target_iv_len = 16;
                break;
            default://SHOULD NOT BE USED
                target_mac_len = 20;
                target_key_len = 16;
                target_iv_len = 16;
                ;
            };

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
        cout<<"APPLICATION_DATA"<<endl;
        if (!key_ready_mbox) {
            //May be a key share request in the future
            cout<<"Key on the MB is not ready!\n";
        }
        else
            decrypt(cipher_suite, NULL, rec, getAppLayerDataDirection(direction));  // You can get correct direction like this
    }
    else
    {
        cout<<"Unknown Content Type"<<endl;
    }
    //TLS record is no need to delete.
}

static long long gettime(struct timeval t1, struct timeval t2) {
    return (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec) ;
}

uint8_t* TLSHandler::getTLSKey(uint8_t* cr, uint8_t* sr, uint16_t cs, FlowKey* flowkey, TCPDataDirection direction)
{
    cout<<"getTLSKey() is called!\n";

    if (!key_ready && cipher_suite == 0xc014) {//Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
        uint8_t* ms = (uint8_t*)getMasterSecret((char*)cr);
        if (ms) {
            cout << "@@ succ getms\n";
            cout << "Begin calc key!" << endl;
            
            unsigned char seed[1000] = {0};
#define STR "key expansion"
            memcpy(seed, STR, strlen(STR));
            int ms_len = 48;
            int key_len = target_key_len;
            int seed_len = strlen(STR);
            memcpy(seed + seed_len, sr, 32);
            seed_len += 32;
            memcpy(seed + seed_len, cr, 32);
            seed_len += 32;
/*
printf("keylen=%d seedlen=%d\n", key_len, seed_len);
for (int j = 0; j < ms_len; ++j) printf("%02x ", ms[j]);printf("\n");
for (int j = 0; j < seed_len; ++j) printf("%02x ", seed[j]);printf("\n");
*/
            uint8_t key_block[1000] = {0};
            int kbsize = 0;
            uint8_t a[20][1000] = {0};
            int a_len[20];
            int i = 0;
            memcpy(a[0], seed, seed_len);
            a_len[0] = seed_len;

            while (kbsize < (target_mac_len + key_len + target_iv_len) * 2) {
                ++i;
                a_len[i] = HMAC_SHA256(ms, ms_len, a[i-1], a_len[i-1], a[i]);
                //printf("tls_a%d: ",i);for (int j = 0; j < a_len[i]; ++j) printf("%02x ", a[i][j]);printf("\n");
                uint8_t msg[1000] = {0};
                memcpy(msg, a[i], a_len[i]);
                memcpy(msg + a_len[i], seed, seed_len);
                int clen = HMAC_SHA256(ms, ms_len, msg, a_len[i] + seed_len, key_block + kbsize);
                kbsize += clen;
            }
            //printf("key_block:\n");
            //for (int j = 0; j < kbsize; ++j) printf("%02x ", key_block[j]);

            
            km.client_write_key_len = key_len;
            memcpy(km.client_write_key, key_block + target_mac_len*2, key_len);
            km.server_write_key_len = key_len;
            memcpy(km.server_write_key, key_block + target_mac_len*2 + key_len, key_len);
            km.client_write_iv_len = target_iv_len;
            memcpy(km.client_write_iv, key_block + target_mac_len*2 + key_len*2, target_iv_len);
            km.server_write_iv_len = target_iv_len;
            memcpy(km.server_write_iv, key_block + target_mac_len*2 + key_len*2 + target_iv_len, target_iv_len);
            
            printf("@@ CALC: CR=");
            for (int i = 0; i < key_len; ++i) printf("%02x", cr[i]&0xff);
            printf("  SR=");
            for (int i = 0; i < key_len; ++i) printf("%02x", sr[i]&0xff);
            printf("  MS=");
            for (int i = 0; i < 48; ++i) printf("%02x", ms[i]&0xff);
            printf("  CWK=");
            for (int i = 0; i < km.client_write_key_len; ++i) printf("%02x", km.client_write_key[i]&0xff);
            printf("  CWIV=");
            for (int i = 0; i < km.client_write_iv_len; ++i) printf("%02x", km.client_write_iv[i]&0xff);
            printf("  SWK=");
            for (int i = 0; i < km.server_write_key_len; ++i) printf("%02x", km.server_write_key[i]&0xff);
            printf("  SWIV=");
            for (int i = 0; i < km.server_write_iv_len; ++i) printf("%02x", km.server_write_iv[i]&0xff);            
            printf("\n");
            

            int keys_len = (km.client_write_key_len + km.client_write_iv_len)*2;
            uint8_t keys[1000];
            memcpy(keys, km.client_write_key, km.client_write_key_len);
            memcpy(keys + km.client_write_key_len, km.client_write_iv, km.client_write_iv_len);
            memcpy(keys + km.client_write_key_len + km.client_write_iv_len, km.server_write_key, km.server_write_key_len);
            memcpy(keys + km.client_write_key_len + km.client_write_iv_len + km.server_write_key_len, km.server_write_iv, km.server_write_iv_len);
            printf("~~~~~~~~~~~keys_len=%d\n", keys_len);
            struct timeval t0;
            gettimeofday(&t0, NULL);
            for (int i = 0; i < 1; ++i) {
            struct timeval t1;
            gettimeofday(&t1, NULL);
            abe = abe_encrypt(keys, keys_len, "CN and (TLS)");
            struct timeval t2;
            gettimeofday(&t2, NULL);
            //ABEFile res2 = abe_decrypt(res.f);
            struct timeval t3;
            gettimeofday(&t3, NULL);
            //printf("ABE: res.len=%d  time#1=%dus  time#2=%dus\n", res.len, gettime(t1, t2), gettime(t2, t3));
            }
            struct timeval te;
            gettimeofday(&te, NULL);
            printf("ABE: total time=%dus\n", gettime(t0, te));
            
            key_ready = true;
        } else {
                cout << "@@ fail getms\n";
        }
    }

    return NULL;
}

int TLSHandler::handleKeys(const uint8_t *payload, unsigned int length)
{
    km.client_write_key_len = target_key_len;
    memcpy(km.client_write_key, payload, target_key_len);
    km.client_write_iv_len = target_iv_len;
    memcpy(km.client_write_iv, payload + target_key_len, target_iv_len);    
    km.server_write_key_len = target_key_len;
    memcpy(km.server_write_key, payload + target_key_len + target_iv_len, target_key_len);
    km.server_write_iv_len = target_iv_len;
    memcpy(km.server_write_iv, payload + target_key_len*2 + target_iv_len, target_iv_len);
            
            printf("@--@  CWK=");
            for (int i = 0; i < km.client_write_key_len; ++i) printf("%02x", km.client_write_key[i]&0xff);
            printf("  CWIV=");
            for (int i = 0; i < km.client_write_iv_len; ++i) printf("%02x", km.client_write_iv[i]&0xff);
            printf("  SWK=");
            for (int i = 0; i < km.server_write_key_len; ++i) printf("%02x", km.server_write_key[i]&0xff);
            printf("  SWIV=");
            for (int i = 0; i < km.server_write_iv_len; ++i) printf("%02x", km.server_write_iv[i]&0xff);            
            printf("\n");
            
            
    key_ready_mbox = true;
}

void TLSHandler::decrypt(uint16_t cs, uint8_t* key, TLSRec* record, AppLayerDataDirection direction)
{
    /// You can use like this:
    /// if(direction == CLIENT_TO_SERVER)
    ///     cout<<"decrypt() is called! CLIENT_TO_SERVER\n";
    /// else if(direction == SERVER_TO_CLIENT)
    ///     cout<<"decrypt() is called! SERVER_TO_CLIENT\n";

    if (key_ready_mbox && direction == CLIENT_TO_SERVER) {
        cout<<"decrypt() is called!\n";
/*    cout<<"@param cs is cipher_suite\n";
    cout<<"@param key is TLS key which is from getTLSKey()\n";
    cout<<"@param record is TLSRec that is waiting for decrypted\n";*/
        //cout<<"APPLICATION_DATA "<<record->length<<" bytes"<<endl;
        //printf("%x\n", record->length);
        unsigned char dec_out[123450];
        AES_KEY dec_key;
        AES_set_decrypt_key(km.client_write_key, km.client_write_key_len * 8, &dec_key); // Size of key is in bits
	    AES_cbc_encrypt(record->tls_payload, dec_out, record->length, &dec_key, km.client_write_iv, AES_DECRYPT);
	    cout << "Plaintext: ";
	    for (int i = 16; i < 200 && i < record->length; ++i) putchar(dec_out[i]);
	    cout << endl;
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
