/*	$OpenBSD: arc4random.c,v 1.53 2015/09/10 18:53:50 bcook Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * SGX-based random number generator
 */

#include <stdint.h>
#include <stddef.h>

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_trts.h"
#else
#include <stdlib.h>
#endif

uint32_t
arc4random(void)
{
//printf("%s\n", __func__);
	uint32_t val;
#ifdef COMPILE_WITH_INTEL_SGX
	sgx_read_rand((unsigned char*)&val, sizeof(val));
#else
	val = (uint32_t)rand();
#endif
	return val;
}

void
arc4random_buf(void *buf, size_t n)
{
//printf("%s\n", __func__);
#ifdef COMPILE_WITH_INTEL_SGX
	sgx_read_rand(buf, n);
#else
	size_t i;
	for (i=0; i<n/sizeof(uint32_t); i++) {
		uint32_t* c = (uint32_t*)buf+i;
		*c = rand();
	}
#endif
}


/*	$OpenBSD: getentropy_linux.c,v 1.41 2015/09/11 11:52:55 deraadt Exp $	*/

/*
 * Copyright (c) 2014 Theo de Raadt <deraadt@openbsd.org>
 * Copyright (c) 2014 Bob Beck <beck@obtuse.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Emulation of getentropy(2) as documented at:
 * http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man2/getentropy.2
 */

/* Use Intel SGX random number generation facilities */

#include <stdint.h>
#include <stddef.h>

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_trts.h"
#else
#include <stdlib.h>
#endif

int	getentropy(void *buf, size_t len);

int
getentropy(void *buf, size_t len)
{
//printf("%s\n", __func__);
	if (len > 256) {
		return (-1);
	}

#ifdef COMPILE_WITH_INTEL_SGX
	sgx_read_rand(buf, len);
#else
	size_t i;
	for (i=0; i<len/sizeof(uint32_t); i++) {
		uint32_t* c = (uint32_t*)buf+i;
		*c = rand();
	}
#endif

	return len;
}

