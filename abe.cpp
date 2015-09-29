#include <cstdio>
#include <iostream>
#include <cstring>
#include <sys/time.h>

#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include "bswabe.h"
#include "abe/common.h"
#include "abe/policy_lang.h"
#include "abe.h"

using namespace std;

static bswabe_pub_t* pub = NULL;
static bswabe_prv_t* prv = NULL;

void abe_init(char *pub_key_file, char *prv_key_file)
{
    printf("abe_init: pub_key=%s prv_key=%s\n", pub_key_file?pub_key_file:"NULL", prv_key_file?pub_key_file:"NULL");
    if (pub_key_file) pub = bswabe_pub_unserialize(suck_file(pub_key_file), 1);
    if (prv_key_file) prv = bswabe_prv_unserialize(pub, suck_file(prv_key_file), 1);
}

static long long gettime(struct timeval t1, struct timeval t2) {
    return (t2.tv_sec - t1.tv_sec) * 1000000 + (t2.tv_usec - t1.tv_usec) ;
}

ABEFile abe_encrypt(unsigned char* input_file, int len, char *policy_)
{
    element_t m;
    bswabe_cph_t* cph;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
    int file_len;
struct timeval t[10];
gettimeofday(&t[0], NULL);
    
	char *policy = parse_policy_lang(policy_);
gettimeofday(&t[1], NULL);
	//printf("#%d _:%s  #%d :%s\n", strlen(policy_), policy_, strlen(policy), policy);
    if( !(cph = bswabe_enc(pub, m, policy)) )
        die("%s", bswabe_error());
gettimeofday(&t[2], NULL);
    free(policy);
gettimeofday(&t[3], NULL);
    
    cph_buf = bswabe_cph_serialize(cph);
	bswabe_cph_free(cph);
gettimeofday(&t[4], NULL);

	plt = g_byte_array_new();
	g_byte_array_set_size(plt, len);
	memcpy(plt->data, input_file, len);
gettimeofday(&t[5], NULL);
	file_len = plt->len;//printf("file_len=%d\n", file_len);
	aes_buf = aes_128_cbc_encrypt(plt, m);
gettimeofday(&t[6], NULL);
	g_byte_array_free(plt, 1);
	element_clear(m);
gettimeofday(&t[7], NULL);

    char *out_file = new char[10000];
	int cnt = write_cpabe_file(out_file, cph_buf, file_len, aes_buf);
gettimeofday(&t[8], NULL);
	//printf("write_cpabe: len=%d\n", cnt);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);
	
	ABEFile res;
	res.f = (unsigned char*)out_file;
	res.len = cnt;
gettimeofday(&t[9], NULL);
for (int i = 0; i < 9; ++i) printf("TIME [%d,%d]: %dus\n", i,i+1,gettime(t[i],t[i+1]));
    return res;
}

ABEFile abe_decrypt(const unsigned char* input_file)
{
	GByteArray* aes_buf;
	GByteArray* plt;
	GByteArray* cph_buf;
	bswabe_cph_t* cph;
	int file_len;
	element_t m;
	
    read_cpabe_file((char*)input_file, &cph_buf, &file_len, &aes_buf);
	cph = bswabe_cph_unserialize(pub, cph_buf, 1);
	if( !bswabe_dec(pub, prv, cph, m) ) {
		fprintf(stderr, "%s", bswabe_error());
		return ABEFile();
    }
	bswabe_cph_free(cph);

	plt = aes_128_cbc_decrypt(aes_buf, m);
	g_byte_array_set_size(plt, file_len);
	g_byte_array_free(aes_buf, 1);
    plt->data[file_len] = 0;
	//spit_file(out_file, plt, 1);
	ABEFile res;
	res.f = (unsigned char*)plt->data;
	res.len = file_len;
	return res;
}
