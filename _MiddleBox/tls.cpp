#include <cstdio>
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/sha.h>
#include "tls.h"

using namespace std;

static vector<KeyRecord> vk;

int hexToBinDigit(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return 0;
}
int hexToBin(char *src, char *dst)
{
    int i = 0;
    int j = 0;
    while (src[i] != '\0') {
        dst[j++] = (hexToBinDigit(src[i]) << 4) + hexToBinDigit(src[i + 1]);
        i += 2;
    }
    return j;
}

void addMasterSecret(char *client_random, char *master_secret)
{
    cout << "@@ addMS " << client_random << " " << master_secret << endl;
    struct KeyRecord kr;
    cout << "@@ " << hexToBin(client_random, kr.cr) << " " << hexToBin(master_secret, kr.ms) << endl;
    vk.push_back(kr);
}

char* getMasterSecret(char *client_random)
{
    for (int i = 0; i < vk.size(); ++i)
        if (memcmp(vk[i].cr, client_random, 32) == 0) {
            return vk[i].ms;
        }
    return NULL;
}
