#ifndef __TLS_H__
#define __TLS_H__

struct KeyRecord {
    char cr[32];//client random
//    char sr[32];//server ramdom
    char ms[48];//master secret
};

struct KeyMaterial {    
    unsigned char client_write_key[128];
    int client_write_key_len;
    
    unsigned char server_write_key[128];
    int server_write_key_len;
    
    unsigned char client_write_iv[128];
    int client_write_iv_len;
    
    unsigned char server_write_iv[128];
    int server_write_iv_len;

};

//client_random and master_secret in Hex
void addMasterSecret(char *client_random, char *master_secret);

//client_random in bin
char* getMasterSecret(char *client_random);

#endif
