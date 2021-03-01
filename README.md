# What is ZeroCache

ZeroCache means neither user credentials (i.e. private keys) nor sensitive data (e.g., HTTPS messages) will be discoverd by any untrusted third-parties (e.g., admin insiders, co-located tenants) both in transit and at rest, because the plaintext information is protected inside Intel SGX enclaves and all input/output flows are encrypted!

Certainly we are glad that you will choose ZeroCache to establish your own services (e.g., CDN serivce) on any clouds that have enabled SGX features!

Welcome and enjoy, feel free to send your feedbacks to lmy2010lmy@gmail.com.

Special Thanks to [Pierre-Louis Aublin](p.aublin@imperial.ac.uk) and his [TaLoS](https://github.com/lsds/TaLoS).


## How to Build
Build LibreSSL:
```
cd libressl-2.8.3/crypto
make -j16
```

Build Proxy:
```
cd nginx-1.18.0-proxy
sh ./proxy.sh
```

Build Server:
```
cd nginx-1.18.0-server
sh ./doit.sh
```


## How to Deploy

```
# setup server
cd nginx-1.18.0-server
./objs/nginx

# set proxy
cd nginx-1.18.0-proxy
./objs/nginx

# benchmark using apache-bench
ab -n 5000 -c 10 https://localhost:8889/index.html
```


## Case Scenarios
1. Gateway
    - TEEX-UCloud Privacy Preserving Queries: mainly used for parsing requests from user's encryted queries, plus statistics data collection.
3. CDN Filter
4. Firewall/IDS
6. Hardened NF
6. Load Balancer


## Technical References

### TEE-Based MiddleBox
1. [SafeBricks: Shielding Network
Functions in the Cloud (NSDI 2018)](https://www.usenix.org/system/files/conference/nsdi18/nsdi18-poddar.pdf)
2. [ENDBOX: Scalable Middlebox Functions Using Client-Side Trusted Execution (DSN 2018)](https://lsds.doc.ic.ac.uk/sites/default/files/dsn18-endbox.pdf)
3. [Slick: Secure Middleboxes using Shielded Execution](https://pdfs.semanticscholar.org/8ca1/436fe1e9bbdb39a92178fa80c7869d92573d.pdf)
4. [LightBox: Full-stack Protected Stateful Middlebox at Lightning](https://arxiv.org/pdf/1706.06261): https://github.com/lightbox-impl/LightBox
5. [ShieldBox: Secure Middleboxes using Shielded Execution (SOSR 2018)](https://www.selisproject.eu/uploadfiles/sosr18-final12.pdf)
6. [Enhancing Security and Privacy of Tor's Ecosystem by Using Trusted Execution Environments (NSDI 2017)](http://ina.kaist.ac.kr/~dongsuh/paper/kim-nsdi17.pdf)
7. [PRI: Privacy Preserving Inspection of Encrypted Network Traffic (Oakland workshop 2016)](https://arxiv.org/pdf/1604.04465): [Slides](https://pdfs.semanticscholar.org/7c36/fb36cacb62a33a703964f07386f58d5e80d5.pdf?_ga=2.255053006.790758260.1548316416-1288022874.1546871297)

### Better TLS
1. [Making TLS and Middleboxes Play Together … Nicely](https://www.cylab.cmu.edu/_files/pdfs/partners/conference2017/Steenkiste.pdf)
2. [And Then There Were More: Secure Communication for More Than Two Parties](https://davidtnaylor.com/mbTLS_slides.pdf)
3. [s2n : an implementation of the TLS/SSL protocols](https://github.com/awslabs/s2n)

### Proxy Projects
1. [Nginx](https://www.nginx.com/)
2. [LVS](https://github.com/alibaba/LVS)
3. [HAProxy](http://www.haproxy.org/)
4. [mitmproxy: An interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers](https://mitmproxy.org/)

As nginx is the most popular proxy and its simplicity in configuration, we use it as a part of our secured middlebox.

### TLS Projects
1. [LibreSSL: Modernizing the codebase, improving security, and applying best practice development processes](http://www.libressl.org/)
2. [BoringSSL: A fork of OpenSSL that is designed to meet Google's needs](https://boringssl.googlesource.com/boringssl/)
3. [OpenSSL: A robust, commercial-grade, full-featured, and Open Source cryptography library](https://www.openssl.org/)

According to [Cryptography and Encryption Libraries](https://cpp.libhunt.com/categories/661-cryptography), LibreSSL has the best code quality (L4). That's why we adopt it inside enclaves.


## Update History

* 2021.3.1
    1. Update to nginx-1.18.0.
    2. Update to libressl-3.2.4 (WIP).

* 2019.1.27
    1. Test with Proxy mode.
    2. Bug fixes for double HTTPS channel.
    3. HTTP body protection within enclave boundary.
    4. Remove `.cpp` files dependency.
    5. Adapted with `DEFS` flag with original `Makefile`.
    6. Add technical references.

* 2019.1.26
    1. Regression Test.

* 2019.1.25
    1. Minimal modifications for libressl-2.4.1.
    2. Fixed `printf`, `strndup` symbols that should've turned out to be undefined originally in the TaLoS project.
    3. Fixed `ssl_session_cache` option for nginx.conf, by supporting the `ocall_get_session_cb_trampoline` method for `ngx_ssl_get_cached_session`.
    4. Try to build with libressl v2.8.3.
    5. Support nginx-1.15.8 with libressl-2.8.3, little ssl modification were made.
    

* 2019.1.24
    1. Using `-U_FORTIFY_SOURCE` instead of `-D_FORTIFY_SOURCE=2`. However, with `FORTIFY_SOURCE` enabled, GCC tries to uses buffer-length aware replacements for functions like `strcpy`, `memcpy`, `memset`, etc.

* 2019.1.21
    1. Merge necessary ecalls to one file.

* 2019.1.20
    1. Split ecalls for nginx, maintain minimal sets, ready to update libressl v2.8.2 (Stable release).
    2. Checked. Original LibreSSL include file will do for the Nginx building. `No Header FILEs dependency.`
    3. Delete `.section	.init` in `cpuid-elf-x86_64.S`, so to omit `-ignore-init-sec-error` sgx-sign error.

* 2019.1.19
    1. Code base clean, remove unnecessary e/ocall interfaces.
    2. Update `doit.sh` script for automatic modification in nginx projects.
    3. Tested with the following versions: `nginx-1.11.0` , `nginx-1.12.2` , `nginx-1.14.2` , `nginx-1.15.8`.
    4. Added interfaces in ecalls.c to define symbols in nginx-1.15.8.

* 2019.1.18
    1. HTTP body protection using AES-128-GCM.
    2. In-Enclave private key and certificate generation. Replace TLS context when establishing a new TLS session (via `SSL_new()`);
    3. Currently cannot support multi-process nginx, as enclave cannot be shared between master/worker processes after fork in `src/os/unix/ngx_process.c`.

* 2019.1.17
    1. Using nginx as the proxy for secure content-based router. Mainline version nginx-1.15.8 as the HTTPS server, stable version nginx-1.14.2 as the proxy.

* 2019.1.10
    1. Update nginx version to latest stable version [1.14.2](http://nginx.org/download/nginx-1.14.2.tar.gz) (2018-12-04).
    2. Modified `nginx-1.14.2/src/event/ngx_event_openssl.c` for compatibility. To look for reasons, please refer to `nginx-1.14.2/debugging.txt`.
    3. Note that the session ticket is disabled, otherwise, more interfaces (sgx-ecalls) should be added.

