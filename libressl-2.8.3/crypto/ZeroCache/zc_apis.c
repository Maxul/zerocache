#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <pthread.h>
#include <dlfcn.h>

#include "sgx_urts.h"
#include "zc_apis.h"
#include "openssl_types.h"
#include "ocalls.h"
#include "hashmap.h"

#include "logging.h"

#include <sgx_uswitchless.h>

#define MAX_PATH 256

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret, const char* fn)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s from %s\n", sgx_errlist[idx].sug, fn);
            printf("Error: %s from %s\n", sgx_errlist[idx].msg, fn);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred: %x from %s.\n", ret, fn);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return -1;
    }

    return 0;
}

/**************************** INIT + ASYNC ECALLS ********************************/

void destroy_enclave(void) {
    if (global_eid != 0) {
        printf("Destroying enclave eid : %lu\n", global_eid);
        sgx_destroy_enclave(global_eid);
        global_eid = 0;
    } else {
        printf("Cannot destroy a non-initialized enclave!\n");
    }
}


void initialize_library(void) {

    /* Initialize the enclave */
    if(initialize_enclave() < 0)
    {
        printf("Error: Enclave initialization failed\n");
        exit(-1);
    }

    printf("Enclave initialization OKAY!\n");

    init_clock_mhz();

    printf("pid : %d, eid : %lu\n", getpid(), global_eid);
}

/**************************** ECALLS ********************************/
int SSL_read(SSL *ssl, void *buf, int num) {
    int retval = 0;
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_read(global_eid, &retval, ssl, buf, num);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);
    return retval;
}

int	BIO_free(BIO *a) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_BIO_free(global_eid, &retval, a);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

long BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    long retval = 0;
    ret = ecall_BIO_int_ctrl(global_eid, &retval, bp, cmd, larg, iarg);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

BIO * BIO_new(BIO_METHOD *type) {
    BIO* retval = NULL;
    int method_in_enclave;

    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_BIO_new(global_eid, &retval, type, &method_in_enclave);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }

    log_exit_ecall(__func__);

    if (type && retval && !method_in_enclave) {
        if (!type->create(retval)) {
            BIO_free(retval);
        }
    }

    return retval;
}

BIO *BIO_new_file(const char *filename, const char *mode) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    BIO* retval = 0;
    ret = ecall_BIO_new_file(global_eid, &retval, filename, mode);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

BIO *BIO_new_mem_buf(const void *buf, int len) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    BIO* retval = 0;
    ret = ecall_BIO_new_mem_buf(global_eid, &retval, buf, len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void BIO_set_flags(BIO *b, int flags) {
    // the BIO is allocated in untrusted memory, so we don't need an ecall
    b->flags |= flags;
}

int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file, int line) {
#if 0
    int retval;
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_CRYPTO_add_lock(global_eid, &retval, pointer, amount, type, file, line);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
#endif
    return 0;
}

void CRYPTO_free(void *ptr) {
    free(ptr);
}

void *CRYPTO_malloc(int num, const char *file, int line) {
    if (num <= 0)
        return NULL;
    return malloc(num);
}


void EC_KEY_free(EC_KEY *key) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EC_KEY_free(global_eid, key);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

EC_KEY *EC_KEY_new_by_curve_name(int nid) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    EC_KEY* retval = 0;
    ret = ecall_EC_KEY_new_by_curve_name(global_eid, &retval, nid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void ERR_clear_error(void ) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_ERR_clear_error(global_eid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_ERR_error_string_n(global_eid, e, buf, len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    } else {
        printf("ERR_error_string_n: %lu %.*s\n", e, (int)len, buf);
    }
    log_exit_ecall(__func__);
}

unsigned long ERR_peek_error(void) {
    log_enter_ecall(__func__);
    unsigned long retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_ERR_peek_error(global_eid, &retval);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

unsigned long ERR_peek_error_line_data(const char **file,int *line, const char **data,int *flags) {
    log_enter_ecall(__func__);
    unsigned long retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_ERR_peek_error_line_data(global_eid, &retval, file, line, data, flags);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

unsigned long ERR_peek_last_error(void) {
    log_enter_ecall(__func__);
    unsigned long retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_ERR_peek_last_error(global_eid, &retval);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int	EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_DigestFinal_ex(global_eid, &retval, ctx, md, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int	EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_DigestInit_ex(global_eid, &retval, ctx, type, impl);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int	EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d, size_t cnt) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_DigestUpdate(global_eid, &retval, ctx, d, cnt);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

EVP_MD_CTX *EVP_MD_CTX_create(void) {
    log_enter_ecall(__func__);
    EVP_MD_CTX* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_MD_CTX_create(global_eid, &retval);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_MD_CTX_destroy(global_eid, ctx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void EVP_PKEY_free(EVP_PKEY *pkey) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_PKEY_free(global_eid, pkey);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);

}

const EVP_MD *EVP_sha1(void) {
    log_enter_ecall(__func__);
    EVP_MD* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_sha1(global_eid, &retval);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return (const EVP_MD*)retval;
}

int i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_i2d_SSL_SESSION(global_eid, &retval, (void*)in, pp);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void OPENSSL_config(const char *config_name) {
    log_enter_ecall(__func__);
    sgx_status_t ret;
    char* str = (char*)malloc(sizeof(*str)*4);
    ret = ecall_OPENSSL_config(global_eid, config_name);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int sk_num(const _STACK *s) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_sk_num(global_eid, &retval, (const void*)s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void *sk_value(const _STACK *s, int v) {
    log_enter_ecall(__func__);
    void* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_sk_value(global_eid, &retval, (const void*)s, v);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

char *SSL_CIPHER_description(const SSL_CIPHER *c, char *buf, int size) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    char* retval;
    ret = ecall_SSL_CIPHER_description(global_eid, &retval, c, buf, size);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        retval = 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

const char * SSL_CIPHER_get_name(const SSL_CIPHER *c) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    char* retval;
    ret = ecall_SSL_CIPHER_get_name(global_eid, &retval, c);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        retval = 0;
    }
    log_exit_ecall(__func__);
    return (const char*) retval;
}

long SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg) {
    long retval = 0;
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_ctrl(global_eid, &retval, ssl, cmd, larg, parg);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);
    return retval;
}

long SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    long retval = 0;
    ret = ecall_SSL_CTX_ctrl(global_eid, &retval, ctx, cmd, larg, parg);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

long SSL_CTX_callback_ctrl(SSL_CTX *c, int i, void (*cb)(void)) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    long retval;
    ret = ecall_SSL_CTX_callback_ctrl(global_eid, &retval, c, i, (void*)cb);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void SSL_CTX_free(SSL_CTX *c) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_free(global_eid, c);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}


STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *s) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    STACK_OF(X509_NAME)* retval;
    ret = ecall_SSL_CTX_get_client_CA_list(global_eid, (void**)&retval, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void *SSL_CTX_get_ex_data(const SSL_CTX *ssl,int idx) {
    log_enter_ecall(__func__);
    void* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_get_ex_data(global_eid, &retval, ssl, idx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
    if (new_func || dup_func || free_func) {
        printf("ecall %s, callbacks are not null, beware!\n",  __func__);
    } else {
        //printf("ecall %s\n", __func__);
    }
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_SSL_CTX_get_ex_new_index(global_eid, &retval, argl, argp, new_func, dup_func, free_func);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

long SSL_CTX_get_timeout(const SSL_CTX *ctx) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    long retval = 0;
    ret = ecall_SSL_CTX_get_timeout(global_eid, &retval, ctx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SSL_CTX* retval = 0;
    ret = ecall_SSL_CTX_new(global_eid, &retval, meth);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy)) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_sess_set_get_cb(global_eid, ctx, (void*)get_session_cb);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess)) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_sess_set_new_cb(global_eid, ctx, (void*)new_session_cb);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess)) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_sess_set_remove_cb(global_eid, ctx, (void*)remove_session_cb);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_default_passwd_cb(global_eid, ctx, (void*)cb);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl,int type,int val)) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_info_callback(global_eid, ctx, (void*)cb);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s, int (*cb) (SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg), void *arg) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_next_protos_advertised_cb(global_eid, s, (void*)cb, arg);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int	SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx, unsigned int sid_ctx_len) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_session_id_context(global_eid, &retval, ctx, sid_ctx, sid_ctx_len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void SSL_CTX_set_verify(SSL_CTX *ctx,int mode, int (*callback)(int, X509_STORE_CTX *)) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_tmp_rsa_callback(global_eid, ctx, mode, (void*)callback);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_verify_depth(global_eid, ctx, depth);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_use_certificate(global_eid, &retval, ctx, x);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_use_PrivateKey(global_eid, &retval, ctx, pkey);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int	SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_use_PrivateKey_file(global_eid, &retval, ctx, file, type);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

SSL * SSL_new(SSL_CTX *ctx) {
    log_enter_ecall(__func__);

    SSL* retval;
    SSL* out_s = (SSL*)malloc(sizeof(*out_s));
    struct ssl3_state_st *s3 = malloc(sizeof(*s3));
    bzero(s3, sizeof(*s3));
    out_s->s3 = s3;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_new(global_eid, &retval, ctx, out_s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);

    return retval;
}

void SSL_free(SSL *ssl) {
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_free(global_eid, ssl);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }

    if (!ssl || ssl->references <= 0) {
        if (ssl) {
            if (ssl->s3) {
                free(ssl->s3);
            }
            free(ssl);
        }
        log_exit_ecall(__func__);

    }
}

int SSL_set_ex_data(SSL *ssl,int idx,void *data) {
    return 1;
}

void *SSL_get_ex_data(const SSL *ssl,int idx) {
    return (NULL);
}

int	SSL_write(SSL *ssl,const void *buf,int num) {
    int retval = 0;
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_write(global_eid, &retval, ssl, buf, num);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);
    return retval;
}

int SSL_do_handshake(SSL *s) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_do_handshake(global_eid, &retval, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

const SSL_CIPHER *SSL_get_current_cipher(const SSL *s) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SSL_CIPHER* retval;
    ret = ecall_SSL_get_current_cipher(global_eid, &retval, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        retval = 0;
    }
    log_exit_ecall(__func__);
    return (const SSL_CIPHER*)retval;
}

int	SSL_get_error(const SSL *s,int ret_code) {
    int retval = 0;
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_get_error(global_eid, &retval, s, ret_code);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);
    return retval;
}

int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_SSL_get_ex_new_index(global_eid, &retval, argl, argp, new_func, dup_func, free_func);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

X509 * SSL_get_peer_certificate(const SSL *s) {
    //avoid an ecall
    X509 *r;
    if ((s == NULL) || (s->session == NULL)) {
        r = NULL;
    } else {
        r = (X509*)s->session;
    }
    return r;
}

BIO * SSL_get_rbio(const SSL *s) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    BIO* retval = 0;
    ret = ecall_SSL_get_rbio(global_eid, &retval, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

char servername[256] = {0};
const char *SSL_get_servername(const SSL *s, const int type) {
    //return '\0' as we don't need to support SNI
    //and the value returned by the ecall is '\0' anyway
    return servername;
}

SSL_SESSION *SSL_get_session(const SSL *ssl) {
    return (ssl->session);
}

int SSL_get_shutdown(const SSL *ssl) {
    return (ssl->shutdown);
}

long SSL_get_verify_result(const SSL *ssl) {
    return (ssl->verify_result);
}

const char *SSL_get_version(const SSL *s) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval;
    ret = ecall_SSL_get_version_as_int(global_eid, &retval, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        retval = 0;
    }
    log_exit_ecall(__func__);

    switch (retval) {
    case DTLS1_VERSION:
        return (SSL_TXT_DTLS1);
    case TLS1_VERSION:
        return (SSL_TXT_TLSV1);
    case TLS1_1_VERSION:
        return (SSL_TXT_TLSV1_1);
    case TLS1_2_VERSION:
        return (SSL_TXT_TLSV1_2);
    default:
        return ("unknown");
    }
}

BIO * SSL_get_wbio(const SSL *s) {
    return (s->wbio);
}

int SSL_library_init(void ) {
    log_enter_ecall(__func__);



    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_SSL_library_init(global_eid, &retval);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void SSL_load_error_strings(void ) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_load_error_strings(global_eid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int SSL_select_next_proto(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, const unsigned char *client, unsigned int client_len) {
    int retval = -1;

    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_select_next_proto(global_eid, &retval, out, outlen, in, inlen, client, client_len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        retval = -1;
    }
    log_exit_ecall(__func__);

    return retval;
}

unsigned char ssl_session_id[32];
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_SESSION_get_id(global_eid, (void*)s, ssl_session_id, len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return (const unsigned char*)0;
    }
    log_exit_ecall(__func__);
    return (const unsigned char*)ssl_session_id;
}

void SSL_set_accept_state(SSL *s) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_set_accept_state(global_eid, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int	SSL_set_fd(SSL *s, int fd) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_set_fd(global_eid, &retval, s, fd);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void SSL_set_quiet_shutdown(SSL *ssl,int mode) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_set_quiet_shutdown(global_eid, ssl, mode);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

void SSL_set_shutdown(SSL *ssl,int mode) {
    ssl->shutdown = mode;
}


void SSL_set_verify(SSL *s, int mode, int (*callback)(int ok,X509_STORE_CTX *ctx)) {
    s->verify_mode = mode;
    if (callback != NULL) s->verify_callback = callback;
}

int SSL_shutdown(SSL *s) {
    int retval = 0;
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_shutdown(global_eid, &retval, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);
    return retval;
}

int SSL_state(const SSL *ssl) {
    return (ssl->state);
}

const SSL_METHOD *SSLv23_method(void) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    SSL_METHOD* retval = 0;
    ret = ecall_SSLv23_method(global_eid, &retval);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return (const SSL_METHOD*)retval;
}

int X509_digest(const X509 *data,const EVP_MD *type, unsigned char *md, unsigned int *len) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_X509_digest(global_eid, &retval, data, type, md, len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void *X509_get_ex_data(X509 *r, int idx) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    void* retval = 0;
    ret = ecall_X509_get_ex_data(global_eid, &retval, r, idx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
    if (new_func || dup_func || free_func) {
        printf("ecall %s, callbacks are not null, beware!\n",  __func__);
    } else {
        //printf("ecall %s\n", __func__);
    }
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_X509_get_ex_new_index(global_eid, &retval, argl, argp, new_func, dup_func, free_func);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

X509_NAME *	X509_get_subject_name(X509 *a) {
    X509_NAME* retval;
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_get_subject_name(global_eid, &retval, a);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

int X509_set_ex_data(X509 *r, int idx, void *arg) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_set_ex_data(global_eid, &retval, r, idx, arg);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

unsigned long ERR_get_error(void) {
    log_enter_ecall(__func__);
    unsigned long retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_ERR_get_error(global_eid, &retval);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int OBJ_sn2nid(const char *s) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_OBJ_sn2nid(global_eid, &retval, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void OPENSSL_add_all_algorithms_noconf(void) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_OPENSSL_add_all_algorithms_noconf(global_eid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int SSL_CTX_set_ex_data(SSL_CTX *ssl,int idx,void *data) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_SSL_CTX_set_ex_data(global_eid, &retval, ssl, idx, data);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

long SSL_CTX_set_timeout(SSL_CTX *ctx,long t) {
    log_enter_ecall(__func__);
    long retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_timeout(global_eid, &retval, ctx, t);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

SSL_SESSION * d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length) {
    log_enter_ecall(__func__);
    SSL_SESSION* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_d2i_SSL_SESSION(global_eid, (void*)&retval, (void**)a, pp, length);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

void SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx, int (*cb) (SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg), void *arg) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_alpn_select_cb(global_eid, ctx, (void*)cb, arg);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_cipher_list(global_eid, &retval, ctx, str);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void X509_free(X509 *a) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_free(global_eid, a);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
    if (cb) {
        printf("ecall %s, callback is not null, beware!\n",  __func__);
    } else {
        //printf("ecall %s\n", __func__);
    }
    log_enter_ecall(__func__);

    X509* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_PEM_read_bio_X509(global_eid, &retval, bp, x, (void*)cb, u);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
    if (cb) {
        printf("ecall %s, callback is not null, beware!\n",  __func__);
    } else {
        //printf("ecall %s\n", __func__);
    }
    log_enter_ecall(__func__);

    X509* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_PEM_read_bio_X509_AUX(global_eid, &retval, bp, x, (void*)cb, u);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void BIO_clear_flags(BIO *b, int flags) {
    // the BIO is allocated in untrusted memory, so we don't need an ecall
    b->flags &= ~flags;
}

char *ERR_error_string(unsigned long e, char *ret) {
    log_enter_ecall(__func__);
    char* retval;
    sgx_status_t retsgx = SGX_ERROR_UNEXPECTED;
    retsgx = ecall_ERR_error_string(global_eid, &retval, e, ret);
    if (retsgx != SGX_SUCCESS) {
        print_error_message(retsgx, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

const char *OBJ_nid2sn(int n) {
    log_enter_ecall(__func__);
    char* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_OBJ_nid2sn(global_eid, &retval, n);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

long BIO_ctrl(BIO *bp,int cmd,long larg,void *parg) {
    log_enter_ecall(__func__);
    long retval;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_BIO_ctrl(global_eid, &retval, bp, cmd, larg, parg);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);
    return retval;
}

__thread SSL_CIPHER* cipher_copy_outside = NULL;
__thread char cipher_name_copy_outside[8192];

const SSL_METHOD fake_TLS_method_data = {
    .version = TLS1_2_VERSION,
};

const SSL_METHOD *TLS_method(void) {
    return &fake_TLS_method_data;
}

void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, RSA *(*cb)(SSL *ssl, int is_export, int keylength)) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_set_tmp_rsa_callback(global_eid, ctx, (void*)cb);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl) {
    return (ssl->ctx);
}

int SSL_use_certificate(SSL *ssl, X509 *x) {
    log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_use_certificate(global_eid, &retval, ssl, x);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey) {
    log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_use_PrivateKey(global_eid, &retval, ssl, pkey);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

_STACK *sk_new_null(void) {
    log_enter_ecall(__func__);
	_STACK* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_sk_new_null(global_eid, (void**)&retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

void sk_pop_free(_STACK *st, void (*func)(void *)) {
    log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_sk_pop_free(global_eid, st, (void*)func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void RAND_seed(const void *buf, int num) {
    return; // we use the sgx specific system to generate random value
}

int RAND_status(void) {
    return 1;
}

int CRYPTO_num_locks(void) {
    return CRYPTO_NUM_LOCKS;
}

unsigned long SSLeay(void) {
    return SSLEAY_VERSION_NUMBER;
}

static __thread EVP_PKEY my_evp_pkey;

int SSL_get_verify_mode(const SSL *s) {
    return (s->verify_mode);
}

int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx, unsigned int sid_ctx_len) {
    if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
        return 0;
    }

    ssl->sid_ctx_length = sid_ctx_len;
    memcpy(ssl->sid_ctx, sid_ctx, sid_ctx_len);
    return 1;
}

void SSL_set_verify_result(SSL *ssl, long arg) {
    ssl->verify_result = arg;
}

const char *SSLeay_version(int type) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    char* retval;
    ret = ecall_SSLeay_version(global_eid, &retval, type);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        retval = 0;
    }
    log_exit_ecall(__func__);
    return (const char*)retval;
}

X509 *SSL_get_certificate(const SSL *ssl) {
    X509* retval = NULL;
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_get_certificate(global_eid, &retval, ssl);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }

    log_exit_ecall(__func__);
    return retval;
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *c) {
    X509_STORE* retval;
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_get_cert_store(global_eid, &retval, c);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

void DH_free(DH *dh) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_DH_free(global_eid, dh);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx) {
    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_get_verify_mode(global_eid, &retval, ctx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *) {
    log_enter_ecall(__func__);
    int (*retval)(int, X509_STORE_CTX *);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_CTX_get_verify_callback(global_eid, (void**)&retval, ctx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u) {
    log_enter_ecall(__func__);
    DH* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_PEM_read_bio_DHparams(global_eid, &retval, bp, x, (void*)cb, u);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}


EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
    log_enter_ecall(__func__);
	EVP_PKEY* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_PEM_read_bio_PrivateKey(global_eid, &retval, bp, x, (void*)cb, u);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx) {
    log_enter_ecall(__func__);
    SSL_CTX* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_set_SSL_CTX(global_eid, &retval, ssl,ctx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

void SSL_set_connect_state(SSL *s) {
    log_enter_ecall(__func__);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_SSL_set_connect_state(global_eid, s);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }

    log_exit_ecall(__func__);
}

void EVP_cleanup(void) {
    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_EVP_cleanup(global_eid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);
}

////////////////////////////////////////////////////////////////////////////////

const char *OpenSSL_version(int type);
#define OPENSSL_VERSION		0
#define OPENSSL_CFLAGS		1
#define OPENSSL_BUILT_ON	2
#define OPENSSL_PLATFORM	3
#define OPENSSL_DIR		4
#define OPENSSL_ENGINES_DIR	5

const char *
OpenSSL_version(int t)
{
    switch (t) {
    case OPENSSL_VERSION:
        return "2.8.3";
    case OPENSSL_BUILT_ON:
        return("built on: date not available");
    case OPENSSL_CFLAGS:
        return("compiler: information not available");
    case OPENSSL_PLATFORM:
        return("platform: information not available");
    case OPENSSL_DIR:
        return "OPENSSLDIR: \"" /*OPENSSLDIR*/ "\"";
    case OPENSSL_ENGINES_DIR:
        return "ENGINESDIR: N/A";
    }
    return("not available");
}

int
SSL_is_server(const SSL *s)
{
    printf("%s\n", __func__);
    return s->server;
}

ASN1_TIME *
X509_getm_notAfter(const X509 *x)
{
    printf("%s\n", __func__);
}

const ASN1_TIME *
X509_get0_notBefore(const X509 *x)
{
    printf("%s\n", __func__);
}

const ASN1_TIME *
X509_get0_notAfter(const X509 *x)
{
    printf("%s\n", __func__);
    return X509_getm_notAfter(x);
}

int X509_check_host(X509 *x, const char *chk, size_t chklen,
                    unsigned int flags, char **peername)
{
    printf("%s\n", __func__);
    if (chk == NULL)
        return -2;
    if (chklen == 0)
        chklen = strlen(chk);
    else if (memchr(chk, '\0', chklen))
        return -2;
    return 0;
}

int
SSL_CTX_set1_groups_list(SSL_CTX *ctx, const char *groups)
{
    printf("%s\n", __func__);
    return 1;//return tls1_set_groups_list(&ctx->internal->tlsext_supportedgroups,
    //&ctx->internal->tlsext_supportedgroups_length, groups);
}

int OPENSSL_init_ssl(uint64_t opts, const void *settings)
{
    initialize_library();

    printf("%s\n", __func__);

    OPENSSL_config(NULL);

    SSL_library_init();
    SSL_load_error_strings();

    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_OPENSSL_add_all_algorithms_noconf(global_eid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
    }
    log_exit_ecall(__func__);

    return 1;
}

int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, uint16_t version)
{
    printf("%s\n", __func__);
    return 0;
}

OCSP_RESPONSE *d2i_OCSP_RESPONSE_bio(BIO *bp, OCSP_RESPONSE **a)
{
    printf("%s\n", __func__);
    return 0;
}

int X509_up_ref(X509 *x)
{
    printf("%s\n", __func__);
    return 0;
}

int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, uint16_t version)
{
    printf("%s\n", __func__);
    return 0;
}

