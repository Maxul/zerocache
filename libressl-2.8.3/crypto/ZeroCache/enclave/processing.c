#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"

#include "http_parser.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h> /* rand */
#include <string.h>
#include <stdarg.h>

#ifdef COMPILE_WITH_INTEL_SGX
extern int printf(const char *format, ...);
#else
#include <stdarg.h>
void printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
#endif

static unsigned long long monotonic_counter = 0;

static http_parser parser;
static http_parser_settings *current_pause_parser;

void processing_ssl_read(char* data, unsigned int len);
void processing_ssl_write(char* data, unsigned int len);
int my_printf(const char* format, ...);

#include <ctype.h>
static inline
void _print_hex(const char* what, const void* v, const unsigned long l)
{
    const unsigned char* p = (unsigned char*)v;
    unsigned long x, y = 0, z;
    my_printf("%s contents: \n", what);
    for (x = 0; x < l; ) {
        my_printf("%02X ", p[x]);
        if (!(++x % 16) || x == l) {
            if((x % 16) != 0) {
                z = 16 - (x % 16);
                if(z >= 8)
                    my_printf(" ");
                for (; z != 0; --z) {
                    my_printf("   ");
                }
            }
            my_printf(" | ");
            for(; y < x; y++) {
                if((y % 8) == 0)
                    my_printf(" ");
                if(isgraph(p[y]))
                    my_printf("%c", p[y]);
                else
                    my_printf(".");
            }
            my_printf("\n");
        }
        else if((x % 8) == 0) {
            my_printf(" ");
        }
    }
}

static inline
void safe_free(void *ptr, int64_t size)
{
    memset_s(ptr, size, 0x0, size);
    free(ptr);
    ptr = NULL;
}

sgx_key_128bit_t key;
uint8_t mac[16] = {0};
uint8_t iv[12] = {0};

void teex_encrypt_data(uint8_t *plain_text, int plain_len, uint8_t *cipher)
{
    memset(iv, 0xee, 12);
    memset(mac, 0xee, 16);

    sgx_status_t sgx_ret = sgx_rijndael128GCM_encrypt(
                               &key, plain_text, plain_len, cipher, iv, 12, NULL, 0, (uint8_t *)(mac));

    if (SGX_SUCCESS != sgx_ret) {
        printf("error encrypting plain text: %d\n", sgx_ret);
    }
}

int teex_decrypt_data(uint8_t *plain_text, int plain_len, uint8_t *cipher, int cipher_len)
{
    sgx_status_t sgx_ret = sgx_rijndael128GCM_decrypt(
                               &key, cipher, cipher_len, plain_text, iv, 12, NULL, 0, (uint8_t *)(mac));

    if (SGX_SUCCESS != sgx_ret) {
        printf("\nError decrypting cipher text. Error code : 0x%x\n", sgx_ret);
    }
    return cipher_len;
}

int read_on_body(http_parser* _, const char* at, size_t length) {
    (void)_;
    //printf("read Body: %.*s\n", (int)length, at);
    //printf("read Body Length: %lu\n", length);

    if (length > 0) {

        uint8_t *cipher_text = (uint8_t *)calloc(1, length);
        teex_encrypt_data(at, length, cipher_text);
        //_print_hex("encrypt_data", cipher_text, length);
        memcpy(at, cipher_text, length);
        safe_free(cipher_text, length);
    }

    return 0;
}

int write_on_body(http_parser* _, const char* at, size_t length) {
    (void)_;
    //printf("write Body: %.*s\n", (int)length, at);
    //printf("write Body Length: %lu\n", length);

    if (length > 0) {

        uint8_t *plain_text = (uint8_t *)calloc(1, length);
        teex_decrypt_data(plain_text, length, at, length);
        //_print_hex("decrypt_data", plain_text, length);
        memcpy(at, plain_text, length);
        safe_free(plain_text, length);

    }

    return 0;
}

void processing_ssl_read(char* data, unsigned int len) {
#if 0
//printf("processing_ssl_read ========> %s\n", data);
    http_parser_settings settings;
    memset(&settings, 0, sizeof(settings));
    settings.on_body = read_on_body;

    http_parser parser;
    http_parser_init(&parser, HTTP_BOTH);
    size_t nparsed = http_parser_execute(&parser, &settings, data, len);

#endif
}

void processing_ssl_write(char* data, unsigned int len) {
#if 0
//printf("processing_ssl_write  ========> \n", data);
    http_parser_settings settings;
    memset(&settings, 0, sizeof(settings));
    settings.on_body = write_on_body;

    http_parser parser;
    http_parser_init(&parser, HTTP_BOTH);
    size_t nparsed = http_parser_execute(&parser, &settings, data, len);

#endif
}
