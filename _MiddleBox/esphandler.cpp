#include<memory.h>
#include<cstdio>
#include<openssl/aes.h>
#include<iostream>
#include<sys/time.h>
#include "esphandler.h"
#include"abe.h"
#include"tcphandler.h"
//#include"tls.h"
using namespace std;

extern int hexToBinDigit(char ch);
extern int hexToBin(char *src, char *dst);

ESPHandler::ESPHandler()
{
    //ctor
}

ESPHandler::~ESPHandler()
{
    //dtor
}

static long long gettime(struct timeval t1, struct timeval t2)
{
    return (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec);
}

bool ESPHandler::parseAndDecrypt(unsigned int length, const uint8_t* payload, uint8_t* dest, unsigned int &plaintlen, int c2s)
{
    //cout<<"---------------------start parseAndDecrypt------------------\n";
    unsigned int spi;
    memcpy(&spi, payload, 4);
    uint8_t iv[16];
    memcpy(iv, payload+8, 16);
    //spi = ntohl(spi);
    //cout<<"SPI:"<<hex<<spi<<dec<<endl;

    //get keys
    espKeyMap_it it = espKeyMap.find(spi);
    KeyMaterial_ESP_Ptr km;
    ABEFile abe;
    abe.len = 0;
    if(it == espKeyMap.end())
    {
        km = getKeys(spi);
        if(km)
        {
            //ABE
            int keys_len = 4 + km->enckeylen + km->authkeylen;
            uint8_t keys[1000];
            memcpy(keys, &spi, 4);
            memcpy(keys + 4, km->enckey, km->enckeylen);
            memcpy(keys + 4 + km->enckeylen, km->authkey, km->authkeylen);
            printf("~~~~~~~~~~~~~~~keys_len=%d\n", keys_len);
            struct timeval t1;
            gettimeofday(&t1, NULL);
            abe = abe_encrypt(keys, keys_len, "CN and (TLS)");
            struct timeval t2;
            gettimeofday(&t2, NULL);
            printf("ABE-encrypt:total time=%lld\n", gettime(t1, t2));
            // struct timeval t3;
            // gettimeofday(&t3, NULL);
            // ABEFile abe2 = abe_decrypt(abe.f);
            // struct timeval t4;
            // gettimeofday(&t4, NULL);
            // printf("ABE-decrypt:total time=%lld\n", gettime(t3, t4));
            uint8_t fake_header[100] = {0};
            uint8_t fake_tcp_header[20] = {0x01, 0xf4, 0x01, 0xf4,  //Ports = 500
                                           0x00, 0x00, 0x00, 0x00,  //seq = 0
                                           0x00, 0x00, 0x00, 0x00,  //ack = 0
                                           0x50, 0x00, 0xff, 0xff,  //hdrlen = 5(*4=20), wnd = 65535
                                           0x00, 0x00, 0x00, 0x00};  //sum = urgptr = 0
            memcpy(fake_header, payload-20-14, 20+14);    //IP header & ETH header
            memcpy(fake_header + 20 + 14, fake_tcp_header, 20);  //TCP header
            sendTCPWithOption_PF_PACKET(fake_header, abe, c2s);
            delete []abe.f;
        }
        else
        {
            cout<<"km is NULL!\n";
            return false;
        }
    }
    else
        km = it->second;

    //cout<<"-------------------------before decrypt-------------------------\n";
    plaintlen = length - 8 - 16 - 12;
    //plaintlen = 40;
    decrypt(plaintlen, payload+8+16, km, iv, dest);     //NOTICE: Authentication Data have 12 bytes in this case
    return true;
}

KeyMaterial_ESP_Ptr ESPHandler::getKeys(unsigned int spi)
{
    //cout<<"------------------------get keys---------------------------\n";
    const char* filepath = "/etc/ipsec.key";
    FILE *file = fopen(filepath, "r");
    if(!file)
        return KeyMaterial_ESP_Ptr();
    char buf[1000];
    while(fgets(buf, 999, file))
    {
        unsigned int _spi;
        char _encalg[50] = {0};
        unsigned int _enckeylen;
        char _enckey[100] = {0};
        char _authalg[50] = {0};
        unsigned int _authkeylen;
        char _authkey[100] = {0};

        sscanf(buf, "%u %s %u %s %s %u %s\n", &_spi, _encalg, &_enckeylen, _enckey, _authalg, &_authkeylen, _authkey);


        if(_spi == spi)
        {
            //construct a new KeyMaterial
            KeyMaterial_ESP_Ptr newkmptr(new KeyMaterial_ESP());
            memcpy(newkmptr->encalg, _encalg, 50);
            newkmptr->enckeylen = _enckeylen;
            //memcpy(newkmptr->enckey, _enckey, 100);
            if(hexToBin(_enckey, (char*)newkmptr->enckey) != _enckeylen)
                cout<<"enckey hextoBin failed\n";
            memcpy(newkmptr->authalg, _authalg, 50);
            newkmptr->authkeylen = _authkeylen;
            //memcpy(newkmptr->authkey, _authkey, 100);
            if(hexToBin(_authkey, (char*)newkmptr->authkey) != _authkeylen)
                cout<<"authkey hextoBin failed\n";
            //printf("%u %s %u %s %s %u %s\n", _spi, newkmptr->encalg, newkmptr->enckeylen, newkmptr->enckey, newkmptr->authalg, newkmptr->authkeylen, newkmptr->authkey);
            cout<<_authkeylen<<"  "<<_enckeylen<<endl;
            //map it
            espKeyMap[spi] = newkmptr;

            return newkmptr;
        }
    }
    return KeyMaterial_ESP_Ptr();
}

int ESPHandler::handleKeys(const uint8_t *payload, unsigned int length)
{
    unsigned int spi;
    KeyMaterial_ESP_Ptr newkmptr(new KeyMaterial_ESP());
    memcpy(&spi, payload, 4);
    memcpy(newkmptr->encalg, "aes", strlen("aes"));
    newkmptr->enckeylen = 16;
    memcpy(newkmptr->enckey, payload + 4, newkmptr->enckeylen);
    memcpy(newkmptr->authalg, "sha1", strlen("sha1"));
    newkmptr->authkeylen = 20;
    memcpy(newkmptr->authkey, payload + 4 + newkmptr->enckeylen, newkmptr->authkeylen);

    espKeyMap[spi] = newkmptr;
}

void ESPHandler::decrypt(unsigned int length, const uint8_t* payload, KeyMaterial_ESP_Ptr km, uint8_t* iv, uint8_t* dest)
{
    //cout<<"---------------------------starting decrypt-----------------------------\n";
    if(strcmp(km->encalg, "aes") == 0)
    {
        uint8_t out[10000] = {0};
        AES_KEY aes_key;
        AES_set_decrypt_key(km->enckey, km->enckeylen*8, &aes_key);
        //uint8_t iv[16] = {0};
        AES_cbc_encrypt(payload, out, length, &aes_key, iv, AES_DECRYPT);
        memcpy(dest, out, 10000);
        //TODO: Padding needs to be removed.
        //for(int i = 0; i < length; i++)
        //    printf("0x")
    }

}
