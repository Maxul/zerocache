
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <openssl/opensslconf.h>

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <openssl/sha.h>

typedef unsigned long long IA32CAP;

IA32CAP OPENSSL_ia32_cpuid(void)
{
    return 0x0;
}
