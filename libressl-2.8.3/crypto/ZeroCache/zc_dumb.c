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
#include "logging.h"
#include "ocalls.h"

extern sgx_enclave_id_t global_eid;

int X509_check_issued(X509 *issuer, X509 *subject) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_check_issued(global_eid, &retval, issuer, subject);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

ASN1_INTEGER *	X509_get_serialNumber(X509 *x) {
    ASN1_INTEGER* retval;
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_get_serialNumber(global_eid, &retval, x);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

ASN1_TIME* X509_get_notBefore(X509* x) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    ASN1_TIME* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_get_notBefore(global_eid, &retval, x);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

ASN1_TIME* X509_get_notAfter(X509* x) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    ASN1_TIME* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_get_notAfter(global_eid, &retval, x);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

void * X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    void* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_get_ext_d2i(global_eid, &retval, x, nid, crit, idx);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

ASN1_STRING *X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    ASN1_STRING* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_NAME_ENTRY_get_data(global_eid, &retval, ne);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    X509_NAME_ENTRY* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_NAME_get_entry(global_eid, &retval, name, loc);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return NULL;
    }
    log_exit_ecall(__func__);
    return retval;
}

int	X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    int retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_NAME_get_index_by_NID(global_eid, &retval, name, nid, lastpos);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

char* X509_NAME_oneline(X509_NAME *a,char *buf,int size) {
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    char* retval;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_X509_NAME_oneline(global_eid, &retval, a, buf, size);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
}

/* for nginx version <= 1.11.0 */

int MD5_Init(MD5_CTX *c) {
#if 0
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_MD5_Init(global_eid, &retval, c);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
#endif
}

int MD5_Update(MD5_CTX *c, const void *data, size_t len) {
#if 0
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_MD5_Update(global_eid, &retval, c, data, len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
#endif
}

int MD5_Final(unsigned char *md, MD5_CTX *c) {
#if 0
    if (global_eid == 0) {
        initialize_library();
    }

    log_enter_ecall(__func__);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = 0;
    ret = ecall_MD5_Final(global_eid, &retval, md, c);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret, __func__);
        return 0;
    }
    log_exit_ecall(__func__);
    return retval;
#endif
}

int SSL_CTX_get_verify_depth(const SSL_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	SSL_CTX_remove_session(SSL_CTX *s, SSL_SESSION *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

SSL_SESSION *SSL_get1_session(SSL *ssl) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void ) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_SESSION_free(SSL_SESSION *ses) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int	SSL_set_session(SSL *to, SSL_SESSION *session) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_set_verify_depth(SSL *s, int depth) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void X509_email_free(STACK_OF(OPENSSL_STRING) *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

X509_NAME *	X509_get_issuer_name(X509 *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509_LOOKUP_METHOD *X509_LOOKUP_file(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_NAME_digest(const X509_NAME *data,const EVP_MD *type, unsigned char *md, unsigned int *len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_STORE_CTX_free(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509 *	X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	X509_STORE_CTX_get_error(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void *	X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509_STORE_CTX *X509_STORE_CTX_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *X509_verify_cert_error_string(long n) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OCSP_cert_status_str(long s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OCSP_response_status_str(long s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_RESPONSE * d2i_OCSP_RESPONSE(OCSP_RESPONSE **a, const unsigned char **in, long len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int RAND_bytes(unsigned char *buf,int num) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void GENERAL_NAMES_free(GENERAL_NAMES *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	i2d_OCSP_REQUEST(OCSP_REQUEST *a, unsigned char **out) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	i2d_OCSP_RESPONSE(OCSP_RESPONSE *a, unsigned char **out) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void OCSP_BASICRESP_free(OCSP_BASICRESP *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void OCSP_CERTID_free(OCSP_CERTID *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void OCSP_REQUEST_free(OCSP_REQUEST *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

OCSP_REQUEST * OCSP_REQUEST_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void OCSP_RESPONSE_free(OCSP_RESPONSE *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

OCSP_BASICRESP * OCSP_response_get1_basic(OCSP_RESPONSE *resp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_RESPONSE * OCSP_RESPONSE_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_response_status(OCSP_RESPONSE *resp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


int PEM_write_bio_X509(BIO *bp, X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ASN1_STRING_free(ASN1_STRING *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

ASN1_STRING* ASN1_STRING_type_new(int type) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BIO_puts(BIO *b, const char *in) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int DH_check(const DH *dh, int *ret) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *EVP_PKEY_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
	//	return PEM_ASN1_read_bio((d2i_of_void *)d2i_X509_CRL, "X509 CRL",bp,(void **)x,cb,u);
}

DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
	//	return PEM_ASN1_read((d2i_of_void *)d2i_DHparams, "DH PARAMETERS",fp,(void **)x,cb,u);
}

int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
	//	return PEM_ASN1_write((i2d_of_void *)i2d_RSAPrivateKey,"RSA PRIVATE KEY",fp,x,enc,kstr,klen,cb,u);
}

void RSA_free(RSA *r) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int SSL_version(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

_STACK *sk_dup(_STACK *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int sk_find(_STACK *st, void *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void sk_free(_STACK *st) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int sk_push(_STACK *st, void *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *SSL_state_string(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_1_client_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_1_server_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_2_client_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_2_server_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_client_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_server_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_alias_set1(X509 *x, unsigned char *name, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


int X509_cmp(const X509 *a, const X509 *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_cmp_current_time(const ASN1_TIME *ctm) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_CRL_free(X509_CRL *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_NAME_free(X509_NAME *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}


int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_STORE_CTX_set_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void *X509V3_EXT_d2i(X509_EXTENSION *ext) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_verify_cert(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

long ASN1_INTEGER_get(const ASN1_INTEGER *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BIO_dump(BIO *bp, const char *s, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *BIO_get_callback_arg(const BIO *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO *BIO_new_fp(FILE *stream, int close_flag) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO *BIO_new_socket(int fd, int close_flag) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BIO_printf(BIO *bio, const char *format, ...) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void BIO_set_callback(BIO *b, long (*cb)(struct bio_st *, int, const char *, int,
    long, long)) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void BIO_set_callback_arg(BIO *b, char *arg) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void ERR_print_errors(BIO *bp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void ERR_print_errors_fp(FILE *fp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}


const char *SSL_alert_desc_string_long(int value) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *SSL_alert_type_string_long(int value) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *SSL_CIPHER_get_version(const SSL_CIPHER *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_get_ext_count(X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *X509_get_pubkey(X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_INFO_free(X509_INFO *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void *sk_shift(_STACK *st) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_get_verify_depth(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void BIO_vfree(BIO *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

OCSP_CERTID *OCSP_CERTID_dup(OCSP_CERTID *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


int X509_STORE_load_locations(X509_STORE *ctx, const char *file, const char *path) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *BN_bn2dec(const BIGNUM *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO *BIO_push(BIO *b, BIO *bio) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, unsigned char *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ASN1_OBJECT_free(ASN1_OBJECT *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

ASN1_STRING *ASN1_STRING_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_TIME_check(ASN1_TIME *t) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO_METHOD *BIO_f_base64(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void BIO_free_all(BIO *bio) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_renegotiate(SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

long SSL_SESSION_get_time(const SSL_SESSION *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_set_state(SSL *ssl, int state) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

const EVP_CIPHER *EVP_aes_256_cbc(void)
{
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int
EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
{
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *
SSL_get_shared_ciphers(const SSL *s, char *buf, int len)
{
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
    unsigned int *len)
{
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
    unsigned *len)
{
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
    unsigned int protos_len)
{
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

unsigned char * ASN1_STRING_data(ASN1_STRING *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_STRING_length(const ASN1_STRING *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	BIO_read(BIO *b, void *data, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO_METHOD *BIO_s_mem(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	BIO_write(BIO *b, const void *data, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ENGINE *ENGINE_get_first(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ENGINE *ENGINE_get_next(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ENGINE *ENGINE_by_id(const char *id) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ENGINE_cleanup(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int ENGINE_free(ENGINE *e) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ENGINE_set_default(ENGINE *e, unsigned int flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ERR_remove_thread_state(const CRYPTO_THREADID *tid) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

const EVP_CIPHER *EVP_aes_128_cbc(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


int	EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const EVP_MD *EVP_sha256(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long sec, long maxsec) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *req, OCSP_CERTID *cid) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status, int *reason, ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME **nextupd) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


int	EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ex) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_OBJECT *X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int err) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ERR_put_error(int lib, int func, int reason, const char *file, int line) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int EC_GROUP_get_curve_name(const EC_GROUP * group) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int EVP_read_pw_string(char *buf, int len, const char *prompt, int verify) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OBJ_nid2ln(int n) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OCSP_crl_reason_str(long s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	RAND_pseudo_bytes(unsigned char *buf, int num) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

_STACK *sk_new(int (*c)(const void *, const void *)) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int (*sk_set_cmp_func(_STACK *sk, int (*c)(const void *, const void *)))(const void *, const void *) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey)) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

RSA * RSA_generate_key(int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SHA1_Init(SHA_CTX *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SHA1_Final(unsigned char *md, SHA_CTX *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

