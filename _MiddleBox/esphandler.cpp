#include<memory.h>
#include<cstdio>
#include<openssl/aes.h>
#include<iostream>
#include "esphandler.h"
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

bool ESPHandler::parseAndDecrypt(unsigned int length, const uint8_t* payload, uint8_t* dest, unsigned int &plaintlen)
{
    cout<<"---------------------start parseAndDecrypt------------------\n";
    unsigned int spi;
    memcpy(&spi, payload, 4);
    uint8_t iv[16];
    memcpy(iv, payload+8, 16);
    //spi = ntohl(spi);
    cout<<"SPI:"<<hex<<spi<<dec<<endl;

    //get keys
    espKeyMap_it it = espKeyMap.find(spi);
    KeyMaterial_ESP_Ptr km;
    if(it == espKeyMap.end())
        km = getKeys(spi);
    else
        km = it->second;

    if(!km)
    {
        cout<<"km is NULL!\n";
        return false;
    }

    cout<<"-------------------------before decrypt-------------------------\n";
    plaintlen = length - 8 - 16;
    //plaintlen = 40;
    decrypt(length-8-16, payload+8+16, km, iv, dest);     //NOTICE: Authentication Data have 12 bytes in this case
    return true;
}

KeyMaterial_ESP_Ptr ESPHandler::getKeys(unsigned int spi)
{
    cout<<"------------------------get keys---------------------------\n";
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
}

void ESPHandler::decrypt(unsigned int length, const uint8_t* payload, KeyMaterial_ESP_Ptr km, uint8_t* iv, uint8_t* dest)
{
    cout<<"---------------------------starting decrypt-----------------------------\n";
    if(strcmp(km->encalg, "aes") == 0)
    {
        uint8_t out[10000] = {0};
        AES_KEY aes_key;
        AES_set_decrypt_key(km->enckey, km->enckeylen*8, &aes_key);
        //uint8_t iv[16] = {0};
        AES_cbc_encrypt(payload, out, length, &aes_key, iv, AES_DECRYPT);
        memcpy(dest, out, 10000);
        //for(int i = 0; i < length; i++)
        //    printf("0x")
    }

}
