#include <cstdio>
#include <iostream>
#include <cstring>

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

ABEFile abe_encrypt(unsigned char* input_file, int len, char *policy_)
{
    element_t m;
    bswabe_cph_t* cph;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
    int file_len;

    
	char *policy = parse_policy_lang(policy_);
	printf("#%d _:%s  #%d :%s\n", strlen(policy_), policy_, strlen(policy), policy);
    if( !(cph = bswabe_enc(pub, m, policy)) )
        die("%s", bswabe_error());
    free(policy);
    
    cph_buf = bswabe_cph_serialize(cph);
	bswabe_cph_free(cph);

	plt = g_byte_array_new();
	g_byte_array_set_size(plt, len);
	memcpy(plt->data, input_file, len);
	
	file_len = plt->len;printf("file_len=%d\n", file_len);
	aes_buf = aes_128_cbc_encrypt(plt, m);
	g_byte_array_free(plt, 1);
	element_clear(m);

    char *out_file = new char[10000];
	int cnt = write_cpabe_file(out_file, cph_buf, file_len, aes_buf);
	printf("write_cpabe: len=%d\n", cnt);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);
	
	ABEFile res;
	res.f = (unsigned char*)out_file;
	res.len = cnt;
    return res;
}

char* abe_decrypt(unsigned char* input_file)
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
		return NULL;
    }
	bswabe_cph_free(cph);

	plt = aes_128_cbc_decrypt(aes_buf, m);
	g_byte_array_set_size(plt, file_len);
	g_byte_array_free(aes_buf, 1);
    plt->data[file_len] = 0;
	//spit_file(out_file, plt, 1);
	return (char*)plt->data;
}
