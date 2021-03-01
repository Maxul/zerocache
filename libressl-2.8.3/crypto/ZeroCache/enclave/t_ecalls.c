#define COMPILE_WITH_INTEL_SGX

#include <stdio.h>

#include "../ssl/ssl_locl.h"

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"
#include "sgx_trts.h"
#include "sgx_spinlock.h"
#include "hashmap.h"
#include "sgx_thread.h"
#endif


#define printf

extern hashmap* get_ssl_hardening();

#ifdef COMPILE_WITH_INTEL_SGX
extern sgx_status_t ocall_malloc(void** retval, size_t size);
extern void ocall_execute_ssl_ctx_info_callback(const SSL *ssl, int type, int val, void* cb);
extern int ocall_pem_password_cb(int* retval, char* buf, int size, int rwflag, void* userdata, void* cb);
extern int ocall_ssl_ctx_callback_ctrl(int* retval, SSL* ssl, int* ad, void* arg, void* cb);
extern int ocall_new_session_callback(int* retval, struct ssl_st* ssl, void* sess, void* cb);
sgx_status_t ocall_next_protos_advertised_cb(int* retval, SSL* s, unsigned char** buf, unsigned int* len, void* arg, void* cb);
#endif
extern void tls_processing_new_connection(const SSL* s);
extern void tls_processing_free_connection(const SSL* s);

#ifdef COMPILE_WITH_INTEL_SGX

int ssl_hardening_initialized = 0;
hashmap* ssl_hardening_map = NULL;
sgx_spinlock_t ssl_hardening_map_lock = SGX_SPINLOCK_INITIALIZER;

hashmap* get_ssl_hardening() {
	int expected = 0;
	int desired = 1;
	if (__atomic_compare_exchange_n(&ssl_hardening_initialized, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		ssl_hardening_map = hashmapCreate(251);
	}
	while (!ssl_hardening_map) {
		// burn cycles
	}

	hashmap* m = (hashmap*)hashmapGet(ssl_hardening_map, (unsigned long)sgx_thread_self());
	if (!m) {
		m = hashmapCreate(251);
		sgx_spin_lock(&ssl_hardening_map_lock);
		//	need a lock on the insert, just to be safe. However each thread will acquire the lock only once during its execution
		hashmapInsert(ssl_hardening_map, (const void*)m, (unsigned long)sgx_thread_self());
		sgx_spin_unlock(&ssl_hardening_map_lock);
	}

//	printf("thread %lu get_ssl_hardening -> %p\n", (unsigned long)sgx_thread_self(), m);

	return m;
}

void SSL_copy_fields_to_out_struct(const SSL* in, SSL* out) {
#if 0 ///FIXME
	out->state = in->state;
	out->verify_mode = in->verify_mode;
	out->verify_result = in->verify_result;
	out->wbio = in->wbio;
	out->shutdown = in->shutdown;
	out->ctx = in->ctx;
	out->verify_callback = in->verify_callback;
	out->session = (SSL_SESSION*)(in->session ? in->session->peer : NULL); // we store the X509* pointer into the SSL_SESSION* field :)
	if (out->s3 && in->s3) { out->s3->flags = in->s3->flags; }
	out->references = in->references;

	SSL_set_session_id_context(out, in->sid_ctx, in->sid_ctx_length);
#endif
}

void SSL_copy_fields_to_in_struct(SSL* in, const SSL* out) {
#if 0 ///FIXME
	//XXX we also want to check the values
	in->state = out->state;
	in->verify_mode = out->verify_mode;
	in->verify_result = out->verify_result;
	in->wbio = out->wbio;
	in->shutdown = out->shutdown;
	in->ctx = out->ctx;
	in->verify_callback = out->verify_callback;
	if (out->s3 && in->s3) { 	in->s3->flags = out->s3->flags; }
	in->references = out->references;

	SSL_set_session_id_context(in, out->sid_ctx, out->sid_ctx_length);
#endif
}

SSL* SSL_get_in_pointer(SSL* out_s) {
	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);
	return in_s;
}

int ocall_alpn_select_cb_wrapper(SSL* s, unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg, void* cb) {

	SSL* in_s = s;
	int retval;

	hashmap* m = get_ssl_hardening();
	SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

	SSL_copy_fields_to_out_struct(in_s, out_s);
	retval = ocall_alpn_select_cb_async_wrapper(out_s, out, outlen, in, inlen, arg, cb);
	SSL_copy_fields_to_in_struct(in_s, out_s);

	return retval;
}

int ocall_next_protos_advertised_cb_wrapper(SSL* s, unsigned char** buf, unsigned int* len, void* arg, void* cb) {

	SSL* in_s = s;
	int retval;

	hashmap* m = get_ssl_hardening();
	SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

	SSL_copy_fields_to_out_struct(in_s, out_s);
	sgx_status_t ret = ocall_next_protos_advertised_cb(&retval, out_s, buf, len, arg, cb);
	if (ret != SGX_SUCCESS) {
		printf("%s ocall error: %d\n", __func__, ret);
		retval = 0;
	}
	SSL_copy_fields_to_in_struct(in_s, out_s);
	return retval;
}

#endif




SSL_SESSION* ocall_get_session_cb_trampoline(SSL* ssl, unsigned char* data, int len, int* copy, void* cb) {
	SSL_SESSION* ret;
	SSL* in_s = ssl;

	hashmap* m = get_ssl_hardening();
	SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

	SSL_copy_fields_to_out_struct(in_s, out_s);
	ocall_get_session_cb((void*)&ret, out_s, data, len, copy, cb);
	SSL_copy_fields_to_in_struct(in_s, out_s);

	return ret;
}





///
int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
int add_ext(X509 *cert, int nid, char *value);

static void set_cert_and_key(SSL_CTX *ctx) {
    static int non_inited = 1;

if (non_inited) {
    BIO *bio_err;

	X509 *zerocache_x509 = NULL;
	EVP_PKEY *zerocache_pkey = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	mkcert(&zerocache_x509, &zerocache_pkey, 2048, 0, 365);

#if 0
	RSA_print_fp(stdout,zerocache_pkey->pkey.rsa,0);
	X509_print_fp(stdout,zerocache_x509);

	PEM_write_PrivateKey(stdout,zerocache_pkey,NULL,NULL,0,NULL, NULL);
	PEM_write_X509(stdout,zerocache_x509);
#endif

    // the order is critical, first load cert, then priv key
    if (SSL_CTX_use_certificate(ctx, zerocache_x509) != 1) {
        fprintf(stderr, "failed to load certificate chain file: \n");
        abort();
    }

    if (SSL_CTX_use_PrivateKey(ctx, zerocache_pkey) != 1) {
        fprintf(stderr, "failed to convert priv key\n");
        abort();
    }

	X509_free(zerocache_x509);
	EVP_PKEY_free(zerocache_pkey);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

    non_inited = 0;
    
    debug_printf("using OWN cert and key\n");
}
    
}

///
SSL *
ecall_SSL_new(SSL_CTX *ctx, SSL* out_s) {
#ifdef COMPILE_WITH_INTEL_SGX


#if 0//ndef USE_OUTSIDE_CERT
    set_cert_and_key(ctx);
#endif

	SSL* s = SSL_new(ctx);

	SSL_copy_fields_to_out_struct(s, out_s);

	hashmap* m = get_ssl_hardening();
	hashmapInsert(m, (const void*)out_s, (unsigned long)s); // map[s] = out_s
	hashmapInsert(m, (const void*)s, (unsigned long)out_s); // map[out_s] = s

	return out_s;
#else
	return SSL_new(ctx);
#endif
}

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"
#include <string.h>

extern sgx_status_t ocall_malloc(void** retval, size_t size);
extern sgx_status_t ocall_realloc(void** retval, void* ptr, size_t size);
extern sgx_status_t ocall_free(void* ptr);
static char* SSLeay_version_buffer = NULL;
#endif

char *
ecall_SSLeay_version(int t) {
	const char* v = SSLeay_version(t);
#ifdef COMPILE_WITH_INTEL_SGX
	size_t len = strlen(v);
	if (!SSLeay_version_buffer) {
		if (len+1 > 64) { // normally SSLeay_version() always returns a string shorter than 64 characters
			return 0;
		}
		ocall_malloc((void**)&SSLeay_version_buffer, 64);
	}
	memcpy(SSLeay_version_buffer, v, len);
	SSLeay_version_buffer[len] = '\0';
	return SSLeay_version_buffer;
#else
	return (char*)v;
#endif
}


void
ecall_SSL_free(SSL *s) {
#ifdef COMPILE_WITH_INTEL_SGX

	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);
	out_s->references = in_s->references-1;
	if (out_s->references <= 0) {
		hashmapRemove(m, (unsigned long)out_s);
		hashmapRemove(m, (unsigned long)in_s);
	}

	// no need for an ocall_free(out_s) as the untrusted code in enclaveshim_ecalls.c does it for us
	s = in_s;
#endif
	SSL_free(s);
}

int
ecall_SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
	return SSL_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
}

int
ecall_SSL_get_error(const SSL *s, int i) {
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	return SSL_get_error(s, i);
}

void
ecall_SSL_set_quiet_shutdown(SSL *s, int mode) {

#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	SSL_set_quiet_shutdown(in_s, mode);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	SSL_set_quiet_shutdown(s, mode);
#endif
}

BIO *
ecall_SSL_get_rbio(const SSL *s)
{
#ifdef COMPILE_WITH_INTEL_SGX

	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	BIO* ret = SSL_get_rbio((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_rbio(s);
#endif
}

int
ecall_SSL_read(SSL *s, void *buf, int num) {
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_read(in_s, buf, num);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_read(s, buf, num);
#endif
}

int
ecall_SSL_write(SSL *s, const void *buf, int num) {
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	// Fix Github issue #13: need to ensure that the buf
	// buffer is allocated outside the enclave, otherwise an
	// attacker could send enclave memory to a remote party
	if (!sgx_is_outside_enclave(buf, num)) {
		return -1;
	}

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_write(in_s, buf, num);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_write(s, buf, num);
#endif
}

int
ecall_SSL_shutdown(SSL *s) {
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_shutdown(in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_shutdown(s);
#endif
}

void
ecall_SSL_set_accept_state(SSL *s)
{
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	SSL_set_accept_state(s);
}

int
ecall_SSL_do_handshake(SSL *s) {
#ifdef COMPILE_WITH_INTEL_SGX

	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	return SSL_do_handshake(s);
}


void ecall_SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, void* cb) {
	SSL_CTX_set_tmp_rsa_callback(ctx, cb);
}

X509_STORE *
ecall_SSL_CTX_get_cert_store(const SSL_CTX *ctx) {
	return SSL_CTX_get_cert_store(ctx);
}

void *
ecall_SSL_CTX_get_ex_data(const SSL_CTX *s, int idx) {
	return SSL_CTX_get_ex_data(s, idx);
}

int
ecall_SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg) {
	return SSL_CTX_set_ex_data(s, idx, arg);
}
int
ecall_SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
	return SSL_CTX_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
}
int
ecall_SSL_state(const SSL *ssl)
{
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)ssl;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, (const SSL*)out_s);
	int ret = SSL_state(in_s);
	SSL_copy_fields_to_out_struct((const SSL*)in_s, out_s);
	return ret;
#else
	return SSL_state(ssl);
#endif
}


SSL_CTX *
ecall_SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx)
{
	return SSL_set_SSL_CTX(ssl, ctx);
}
int
ecall_SSL_get_shutdown(const SSL *s) {
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_get_shutdown((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_shutdown(s);
#endif
}
void
ecall_SSL_set_shutdown(SSL *s, int mode) {
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	SSL_set_shutdown(in_s, mode);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	SSL_set_shutdown(s, mode);
#endif
}
SSL_CIPHER *
ecall_SSL_get_current_cipher(const SSL *s)
{
	return (SSL_CIPHER*)SSL_get_current_cipher(s);
}

X509 *
ecall_SSL_get_certificate(const SSL *s) {
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	return SSL_get_certificate(in_s);
#else
	return SSL_get_certificate(s);
#endif
}

int
ecall_SSL_get_version_as_int(const SSL *s)
{
	return s->version;
}
void
ecall_SSL_set_connect_state(SSL *s) {
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	SSL_set_connect_state(s);
}
void
ecall_SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth) {
	SSL_CTX_set_verify_depth(ctx, depth);
}

#ifdef COMPILE_WITH_INTEL_SGX
int (*ssl_ctx_set_verify_callback_address)(int, X509_STORE_CTX *) = NULL;
int ssl_ctx_set_verify_fake_callback(int mode, X509_STORE_CTX *ctx) {
	if (ssl_ctx_set_verify_callback_address) {
		//TODO: make ocall
		fprintf(0, "need to call callback ssl_ctx_set_verify_callback_address\n");
	}
	return 0;
}
#endif

void ecall_SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void* callback) {
	int (*cb)(int, X509_STORE_CTX *);
#ifdef COMPILE_WITH_INTEL_SGX
	ssl_ctx_set_verify_callback_address = (int (*)(int, X509_STORE_CTX *))callback;
	cb = ssl_ctx_set_verify_fake_callback;
#else
	cb = (int (*)(int, X509_STORE_CTX *))callback;
#endif
	SSL_CTX_set_verify(ctx, mode, cb);
}


#ifdef COMPILE_WITH_INTEL_SGX
static void* default_passwd_callback_ocall = 0;

int pem_password_cb_for_ocall(char *buf, int size, int rwflag, void *userdata) {
	if (default_passwd_callback_ocall) {
		int retval;
		ocall_pem_password_cb(&retval, buf, size, rwflag, userdata, default_passwd_callback_ocall);
		return retval;
	} else {
		return -1;
	}
}

void ecall_SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, void *cb) {
	default_passwd_callback_ocall = cb;
	SSL_CTX_set_default_passwd_cb(ctx, pem_password_cb_for_ocall);
}
#else
void ecall_SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, void *cb) {
	SSL_CTX_set_default_passwd_cb(ctx, (pem_password_cb*)cb);
}
#endif

 void
ecall_SSL_CTX_free(SSL_CTX *a) {
	SSL_CTX_free(a);
}
SSL_CTX *
ecall_SSL_CTX_new(const SSL_METHOD *meth) {
	return SSL_CTX_new(meth);
}
void
ecall_SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx, void *cb, void *arg)
{
	int (*callback) (SSL *ssl, const unsigned char **out, unsigned char *outlen,
	    const unsigned char *in, unsigned int inlen, void *arg) = (int (*) (SSL *ssl, const unsigned char **out, unsigned char *outlen,
	    	    const unsigned char *in, unsigned int inlen, void *arg))cb;
	SSL_CTX_set_alpn_select_cb(ctx, callback, arg);
}

int
ecall_SSL_set_alpn_protos(SSL *ssl, const unsigned char* protos, unsigned int protos_len) {
    int retval = -1;
#ifdef COMPILE_WITH_INTEL_SGX
    SSL* out_s = (SSL*)ssl;

	 hashmap* m = get_ssl_hardening();
	 SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	retval = SSL_set_alpn_protos(in_s, protos, protos_len);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	retval = SSL_set_alpn_protos(ssl, protos, protos_len);
#endif
    return retval;
}

void ecall_SSL_CTX_set_next_proto_select_cb(SSL_CTX *s, void* cb, void *arg) {
	int (*callback)(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) =
			(int (*)(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg))cb;
	SSL_CTX_set_next_proto_select_cb(s, callback, arg);
}

void ecall_SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s, void *cb, void *arg) {
	int (*callback) (SSL *ssl,  const unsigned char **out, unsigned int *outlen, void *arg) = (int (*) (SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg))cb;
	SSL_CTX_set_next_protos_advertised_cb(s, callback, arg);
}

int
ecall_SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
    const unsigned char *server, unsigned int server_len,
    const unsigned char *client, unsigned int client_len)
{
	return SSL_select_next_proto(out, outlen, server, server_len, client, client_len);
}

void ecall_SSL_get_servername(const SSL *s, int type, char* servername, int* len) {
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	const char* sn = SSL_get_servername((const SSL*)in_s, type);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	const char* sn = SSL_get_servername(s, type);
#endif
	if (sn == NULL) {
		servername[0] = '\0';
		*len = 0;
	} else {
		*len = strlen(sn);
		memcpy(servername, sn, *len);
	}
}

int
ecall_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
	return SSL_CTX_set_cipher_list(ctx, str);
}

#ifdef COMPILE_WITH_INTEL_SGX

void* ssl_ctx_info_cb_address = 0;

void ssl_ctx_info_fake_cb(const SSL *ssl, int type, int val) {
	/*
	 * From the documentation ( man SSL_CTX_set_info_callback):
	 *        When setting up a connection and during use, it is possible to obtain
	 *        state information from the SSL/TLS engine. When set, an information
	 *        callback function is called whenever the state changes, an alert
	 *        appears, or an error occurs.
	 */
	// do not use this callback in Apache (not needed). However nginx requires it
	if (ssl_ctx_info_cb_address) {
		hashmap* m = get_ssl_hardening();
		SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)ssl);

		SSL_copy_fields_to_out_struct(ssl, out_s);
		ocall_execute_ssl_ctx_info_callback(out_s, type, val, ssl_ctx_info_cb_address);
		SSL_copy_fields_to_in_struct((SSL*)ssl, (const SSL*)out_s);
	}
}
#endif

#ifdef COMPILE_WITH_INTEL_SGX
static void* callback_address = 0;

static int callback_trampoline(SSL* ssl, int* ad, void* arg) {
	return SSL_TLSEXT_ERR_OK;
	// don't call this callback. It is used for SNI stuff that we don't need
	int ret = 0;
	if (callback_address) {
		hashmap* m = get_ssl_hardening();
		SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)ssl);

		SSL_copy_fields_to_out_struct(ssl, out_s);
		ocall_ssl_ctx_callback_ctrl(&ret, out_s, ad, arg, (void*)callback_address);
		SSL_copy_fields_to_in_struct(ssl, out_s);
	}
	return ret;
}

long
ecall_SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void *cb) {
	if (cmd != SSL_CTRL_SET_TLSEXT_SERVERNAME_CB) {
		// we don't handle other cases
		return 0;
	} else {
		callback_address = cb;
		return SSL_CTX_callback_ctrl(ctx, cmd, (void (*)(void))callback_trampoline);
	}
}
#endif

long ecall_SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg) {//
	return SSL_CTX_ctrl(ctx, cmd, larg, parg);
}

long
ecall_SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
{
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	long ret = SSL_ctrl(in_s, cmd, larg, parg);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_ctrl(s, cmd, larg, parg);
#endif
}

void* ecall_SSL_CTX_get_verify_callback(const SSL_CTX *ctx)
{
	return (void*)SSL_CTX_get_verify_callback(ctx);
}

int
ecall_SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
	return SSL_CTX_get_verify_mode(ctx);
}

int
ecall_SSL_set_fd(SSL *s, int fd) {
#ifdef COMPILE_WITH_INTEL_SGX

	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_set_fd(in_s, fd);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_set_fd(s, fd);
#endif
}

BIO *
ecall_SSL_get_wbio(const SSL *s)
{
#ifdef COMPILE_WITH_INTEL_SGX

	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	BIO* ret = SSL_get_wbio((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_wbio(s);
#endif
}

int
ecall_SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx,
    unsigned int sid_ctx_len) {

	return SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);
}

void*
ecall_SSL_CTX_get_client_CA_list(const SSL_CTX *ctx) {
	return SSL_CTX_get_client_CA_list(ctx);
}

void
ecall_SSL_CTX_set_info_callback(SSL_CTX *ctx, void *cb)
{
#if 0
#ifdef COMPILE_WITH_INTEL_SGX
    extern void* ssl_ctx_info_cb_address;
	ssl_ctx_info_cb_address = cb;
	cb = ssl_ctx_info_fake_cb;
#endif
	SSL_CTX_set_info_callback(ctx, (void(*)(const SSL*, int, int))cb);
#endif
}

void ecall_SSL_SESSION_get_id(void* s, unsigned char* buf, unsigned int *len) {
	const unsigned char* sid = SSL_SESSION_get_id((const SSL_SESSION*)s, len);
	memcpy((void*)buf, (const void*)sid, (size_t)*len);
}
long
ecall_SSL_SESSION_set_timeout(SSL_SESSION *s, long t) {
	return SSL_SESSION_set_timeout(s, t);
}
long
ecall_SSL_CTX_set_timeout(SSL_CTX *s, long t) {
	return SSL_CTX_set_timeout(s, t);
}
long
ecall_SSL_CTX_get_timeout(const SSL_CTX *s) {
	return SSL_CTX_get_timeout(s);
}
void
ecall_SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,
    void* cb) {
	int (*callback)(struct ssl_st *ssl, SSL_SESSION *sess) = (int (*)(struct ssl_st *ssl, SSL_SESSION *sess))cb;
	SSL_CTX_sess_set_new_cb(ctx, callback);
}
void
ecall_SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void *cb)
{
	void (*callback)(SSL_CTX *ctx, SSL_SESSION *sess) = (void (*)(SSL_CTX *ctx, SSL_SESSION *sess))cb;
	SSL_CTX_sess_set_remove_cb(ctx, callback);
}
void
ecall_SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, void* cb)
{
	SSL_SESSION *(*callback)(struct ssl_st *ssl, unsigned char *data, int len, int *copy) = (SSL_SESSION *(*)(struct ssl_st *ssl, unsigned char *data, int len, int *copy))cb;
	SSL_CTX_sess_set_get_cb(ctx, callback);
}


int
ecall_SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey) {
	return SSL_CTX_use_PrivateKey(ctx, pkey);
}

int
ecall_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
	return SSL_CTX_use_PrivateKey_file(ctx, file, type);
}

int
ecall_SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file) {
	return SSL_CTX_use_certificate_chain_file(ctx, file);
}

#ifdef COMPILE_WITH_INTEL_SGX
extern SSL* SSL_get_in_pointer(SSL* out_s);
#endif

int
ecall_SSL_use_certificate(SSL *ssl, X509 *x)
{
#ifdef COMPILE_WITH_INTEL_SGX
	ssl = SSL_get_in_pointer(ssl);
#endif
	return SSL_use_certificate(ssl, x);
}

int ecall_SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x) {debug_printf("%s %d\n", __func__, __LINE__);
	return SSL_CTX_use_certificate(ctx, x);
}

int
ecall_SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)
{
#ifdef COMPILE_WITH_INTEL_SGX
	ssl = SSL_get_in_pointer(ssl);
#endif
	return SSL_use_PrivateKey(ssl, pkey);
}

#include <stdio.h>

#include <openssl/opensslconf.h>

#include <openssl/asn1.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif

int
ecall_X509_digest(const X509 *data, const EVP_MD *type, unsigned char *md,
    unsigned int *len)
{
	return X509_digest(data, type, md, len);
}

EVP_MD_CTX *
ecall_EVP_MD_CTX_create(void) {
	return EVP_MD_CTX_create();
}

int
ecall_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
	return EVP_DigestInit_ex(ctx, type, impl);
}
int
ecall_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	return EVP_DigestUpdate(ctx, data, count);
}

/* The caller can assume that this removes any secret data from the context */
int
ecall_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
	return EVP_DigestFinal_ex(ctx, md, size);
}

void
ecall_EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)
{
	return EVP_MD_CTX_destroy(ctx);
}

X509 *
ecall_X509_new(void)
{
	return X509_new();
}
void
ecall_X509_free(X509 *a) {
	return X509_free(a);
}
int
ecall_X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
	return X509_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
}
int
ecall_X509_set_ex_data(X509 *r, int idx, void *arg) {
	return X509_set_ex_data(r, idx, arg);
}
void *
ecall_X509_get_ex_data(X509 *r, int idx) {
	return X509_get_ex_data(r, idx);
}

X509 *ecall_PEM_read_bio_X509(BIO *bp, X509 **x, void *cb, void *u) {
	return PEM_read_bio_X509(bp, x, (pem_password_cb*)cb, u);
}

X509 *ecall_PEM_read_bio_X509_AUX(BIO *bp, X509 **x, void *cb, void *u)
{
	return PEM_read_bio_X509_AUX(bp, x, (pem_password_cb*)cb, u);
}

unsigned long
ecall_ERR_peek_error_line_data(const char **file, int *line,
    const char **data, int *flags)
{
	return ERR_peek_error_line_data(file, line, data, flags);
}
unsigned long
ecall_ERR_peek_last_error(void) {
	return ERR_peek_last_error();
}
void
ecall_ERR_error_string_n(unsigned long e, char *buf, size_t len) 
{
	ERR_error_string_n(e, buf, len);
}

void
ecall_ERR_free_strings(void) {
	ERR_free_strings();
}

void
ecall_ERR_clear_error(void) {
	ERR_clear_error();
}
unsigned long
ecall_ERR_get_error(void)
{
	return ERR_get_error();
}
unsigned long
ecall_ERR_peek_error(void)
{
	return ERR_peek_error();
}

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"

extern sgx_status_t ocall_malloc(void** ptr, size_t size);

static char* ERR_error_string_str = NULL;
#endif

char *
ecall_ERR_error_string(unsigned long e, char *ret) {
	char *encbuf = ERR_error_string(e, ret);

#ifdef COMPILE_WITH_INTEL_SGX
	if (!ERR_error_string_str) {
		ocall_malloc((void**)&ERR_error_string_str, 8192);
	}

	size_t len = strlen(encbuf);
	if (len > 8191) { len = 8191; }
	memcpy(ERR_error_string_str, encbuf, len);
	ERR_error_string_str[len] = '\0';

	if (ret == NULL) { ret = ERR_error_string_str; }
	return ERR_error_string_str;
#else
	return encbuf;
#endif
}

EC_KEY *
ecall_EC_KEY_new_by_curve_name(int nid) {
	return EC_KEY_new_by_curve_name(nid);
}
void 
ecall_EC_KEY_free(EC_KEY * r) {
	EC_KEY_free(r);
}

void
ecall_EVP_cleanup(void)
{
	EVP_cleanup();
}

const EVP_MD *
ecall_EVP_sha1(void) {
	return EVP_sha1();
}

////////////////////////////////////////////////////////////////////////////////\

int
ecall_SSL_library_init(void) {
	return SSL_library_init();
}

void
ecall_SSL_load_error_strings(void) {
	SSL_load_error_strings();
}

const SSL_METHOD *
ecall_SSLv23_method(void) {
	return SSLv23_method();
}

void
ecall_OPENSSL_config(const char *config_name) {
	OPENSSL_config(config_name);
}

void
ecall_OPENSSL_add_all_algorithms_noconf(void)
{
	OPENSSL_add_all_algorithms_noconf();
}

BIO *
ecall_BIO_new_file(const char *filename, const char *mode) {
	return BIO_new_file(filename, mode);
}

BIO *
ecall_BIO_new_mem_buf(const void *buf, int len) {
	return BIO_new_mem_buf(buf, len);
}

int
ecall_sk_num(const void *st) {
	return sk_num((const _STACK*)st);
}

void *
ecall_sk_value(const void *st, int i)
{
	return sk_value(st, i);
}

int
ecall_OBJ_sn2nid(const char *s) {
	return OBJ_sn2nid(s);
}


long
ecall_BIO_int_ctrl(BIO *b, int cmd, long larg, int iarg)
{
	return BIO_int_ctrl(b, cmd, larg, iarg);
}

long
ecall_BIO_ctrl(BIO *b, int cmd, long larg, void *parg) {
	return BIO_ctrl(b, cmd, larg, parg);
}

BIO *
ecall_BIO_new(BIO_METHOD *method, int* method_in_enclave) {
	return BIO_new(method);
}

int ecall_BIO_free(BIO *a) {
	return BIO_free(a);
}

char *
ecall_SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int len) {
	return SSL_CIPHER_description(cipher, buf, len);
}

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"

extern sgx_status_t ocall_malloc(void** retval, size_t size);

char* SSL_CIPHER_name_buffer = NULL;
#endif

const char *
ecall_SSL_CIPHER_get_name(const SSL_CIPHER *c)
{
	const char* ret = SSL_CIPHER_get_name(c);
#ifdef COMPILE_WITH_INTEL_SGX
	if (!SSL_CIPHER_name_buffer) {
		ocall_malloc((void*)&SSL_CIPHER_name_buffer, 8192);
	}
	size_t s = strlen(ret);
	memcpy(SSL_CIPHER_name_buffer, ret, s);
	SSL_CIPHER_name_buffer[s] = '\0';
	return SSL_CIPHER_name_buffer;
#else
	return ret;
#endif
}

int
ecall_i2d_SSL_SESSION(void* in, unsigned char **pp) {
	return i2d_SSL_SESSION((SSL_SESSION*)in, pp);
}

void*
ecall_d2i_SSL_SESSION(void **a, const unsigned char **pp, long length) {
	return (void*)d2i_SSL_SESSION((SSL_SESSION**)a, pp, length);
}

void
ecall_DH_free(DH *r)
{
	DH_free(r);
}

void
ecall_EVP_PKEY_free(EVP_PKEY *x) {
	EVP_PKEY_free(x);
}

X509_NAME *
ecall_X509_get_subject_name(X509 *a) {
	return X509_get_subject_name(a);
}

ASN1_OBJECT* X509_get_cert_key_algor_algorithm(X509* x) {
	return x->cert_info->key->algor->algorithm;
}

ASN1_OBJECT* ecall_X509_get_cert_key_algor_algorithm(X509* x) {
	return X509_get_cert_key_algor_algorithm(x);
}

ASN1_INTEGER *
ecall_X509_get_serialNumber(X509 *a) {
	return X509_get_serialNumber(a);
}

int
ecall_X509_check_private_key(X509 *x, EVP_PKEY *k) {
	return X509_check_private_key(x, k);
}

ASN1_TIME* ecall_X509_get_notBefore(X509* x) {
	return X509_get_notBefore(x);
}

ASN1_TIME* ecall_X509_get_notAfter(X509* x) {
	return X509_get_notAfter(x);
}

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"

extern sgx_status_t ocall_malloc(void** retval, size_t size);

char* OBJ_nid2sn_buffer = NULL;
#endif

char *
ecall_OBJ_nid2sn(int n) {
	char* str = (char*)OBJ_nid2sn(n);
#ifdef COMPILE_WITH_INTEL_SGX
	if (!OBJ_nid2sn_buffer) {
		ocall_malloc((void**)&OBJ_nid2sn_buffer, 8192);
	}
	size_t s = strlen(str);
	//XXX PL: we might have a concurrency problem here...
	memcpy(OBJ_nid2sn_buffer, str, s);
	OBJ_nid2sn_buffer[s] = '\0';

	str = OBJ_nid2sn_buffer;
#endif
	return str;
}

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"

extern sgx_status_t ocall_malloc(void** retval, size_t size);

char* X509_name_online_buffer = NULL;
#endif
char *
ecall_X509_NAME_oneline(X509_NAME *a, char *buf, int len)
{
#ifdef COMPILE_WITH_INTEL_SGX
	if (!buf) {
		if (!X509_name_online_buffer) {
			ocall_malloc((void**)&X509_name_online_buffer, 8192);
		}
		return X509_NAME_oneline(a, X509_name_online_buffer, len);
	} else {
#endif
		return X509_NAME_oneline(a, buf, len);
#ifdef COMPILE_WITH_INTEL_SGX
	}
#endif
}

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"

extern sgx_status_t ocall_malloc(void** retval, size_t size);

BASIC_CONSTRAINTS *out_bc = NULL;
BASIC_CONSTRAINTS *in_bc = NULL; // need to free the objet later, so save the pointer
#endif

void *
ecall_X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx) {
	void* ret = X509_get_ext_d2i(x, nid, crit, idx);

#ifdef COMPILE_WITH_INTEL_SGX
	// to make apache transparent, copy the basic constraints outside the enclave
	// if the ecall returns a NID_basic_constraints object
	if (nid == NID_basic_constraints) {
		if (!out_bc) {
			ocall_malloc((void**)&out_bc, sizeof(*out_bc));
		}
		in_bc = (BASIC_CONSTRAINTS*)ret;
		out_bc->ca = in_bc->ca;
		out_bc->pathlen = in_bc->pathlen;
		return out_bc;
	} else {
#endif
		return ret;
#ifdef COMPILE_WITH_INTEL_SGX
	}
#endif
}

#ifdef COMPILE_WITH_INTEL_SGX
pem_password_cb* pem_read_bio_dhparams_cb_addr = NULL;
int pem_read_bio_dhparams_fake_cb(char *buf, int size, int rwflag, void *userdata) {
	fprintf(0, "%s:%s:%i need to implement callback\n", __FILE__, __func__, __LINE__);
	if (pem_read_bio_dhparams_cb_addr) {
		//TODO ocall(pem_read_bio_dhparams_cb_addr, buf, size, rwflag, userdata);
	}
	return 0;
}
#endif

DH *ecall_PEM_read_bio_DHparams(BIO *bp, DH **x, void* func, void *u) {
	pem_password_cb* cb;
#ifdef COMPILE_WITH_INTEL_SGX
	pem_read_bio_dhparams_cb_addr = (pem_password_cb*)func;
	cb = pem_read_bio_dhparams_fake_cb;
#else
	cb = (pem_password_cb*)func;
#endif
	return PEM_read_bio_DHparams(bp, x, cb, u);
}

#ifdef COMPILE_WITH_INTEL_SGX
pem_password_cb* pem_read_bio_privatekey_cb_address = NULL;

int pem_read_bio_privatekey_fake_cb(char *buf, int size, int rwflag, void *userdata) {
	if (pem_read_bio_privatekey_cb_address) {
		fprintf(0, "need to call pem_read_bio_privatekey_cb_address\n");
	}
	return 0;
}
#endif

EVP_PKEY* ecall_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, void* cb, void *u) {
#ifdef COMPILE_WITH_INTEL_SGX
	pem_read_bio_privatekey_cb_address = (pem_password_cb*)cb;
	pem_password_cb* callback = pem_read_bio_privatekey_fake_cb;
#else
	pem_password_cb* callback = (pem_password_cb*)cb;
#endif
	return PEM_read_bio_PrivateKey(bp, x, callback, u);
}

int
ecall_X509_check_issued(X509 *issuer, X509 *subject) {
	return X509_check_issued(issuer, subject);
}

ASN1_OBJECT* X509_get_algorithm(X509* ptr) {
	return ptr->cert_info->key->algor->algorithm;
}

ASN1_OBJECT* ecall_X509_get_algorithm(X509* ptr) {
	return X509_get_algorithm(ptr);
}

int
ecall_X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos) {
	return X509_NAME_get_index_by_NID(name, nid, lastpos);
}

int
ecall_X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf, int len) {
	return X509_NAME_get_text_by_NID(name, nid, buf, len);
}

X509_NAME_ENTRY *
ecall_X509_NAME_get_entry(X509_NAME *name, int loc) {
	return X509_NAME_get_entry(name, loc);
}

ASN1_STRING *
ecall_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne)
{
	return X509_NAME_ENTRY_get_data(ne);
}

void*
ecall_sk_new_null(void) {
	return (void*)sk_new_null();
}

void ocall_sk_pop_free_cb_wrapper(void* data, void* cb) {
	sgx_status_t ret = ocall_sk_pop_free_cb(data, cb);
	if (ret != SGX_SUCCESS) {
		printf("%s ocall error: %d\n", __func__, ret);
	}
}

#ifdef COMPILE_WITH_INTEL_SGX
extern void ocall_sk_pop_free_cb_wrapper(void* data, void* cb);

static void* sk_pop_free_cb_addr = NULL;
void sk_pop_free_fake_cb(void* data) {
	if (sk_pop_free_cb_addr) {
		ocall_sk_pop_free_cb_wrapper(data, sk_pop_free_cb_addr);
	}
}
#endif

void
ecall_sk_pop_free(void *st, void* cb)
{
#ifdef COMPILE_WITH_INTEL_SGX
	sk_pop_free_cb_addr = cb;
	sk_pop_free((_STACK*)st, (void (*)(void *))sk_pop_free_fake_cb);
#else
	sk_pop_free((_STACK*)st, (void (*)(void *))cb);
#endif
}

