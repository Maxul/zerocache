
#include <pthread.h>
#include <stdio.h>

#include <openssl/objects.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "cryptlib.h"

pthread_t pthread_self()
{
    return 7777;
}

int pthread_once(pthread_once_t *once_control, void (*init_routine) (void))
{
    return 0;
}
