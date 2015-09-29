#pragma once

struct ABEFile {
    ABEFile() { f=NULL;len=0;}
    unsigned char *f;
    int len;
};

void abe_init(char *pub_key_file, char *prv_key_file);
ABEFile abe_encrypt(unsigned char* input_file, int len, char *policy_);
ABEFile abe_decrypt(const unsigned char* input_file);
