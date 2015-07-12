#pragma once

struct ABEFile {
    unsigned char *f;
    int len;
};

void abe_init(char *pub_key_file, char *prv_key_file);
ABEFile abe_encrypt(unsigned char* input_file, int len, char *policy_);
char* abe_decrypt(unsigned char* input_file);
