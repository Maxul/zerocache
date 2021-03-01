rm enclave.signed.so
make clean

./configure --prefix=./install --with-openssl=../libressl-2.8.3 --with-http_ssl_module --with-threads --with-file-aio --without-pcre --with-http_v2_module --without-http_rewrite_module

sed -i -e '/..\/libressl-2.8.3\/.openssl\/include\/openssl\/ssl.h/'d objs/Makefile
sed -i -e '/then $(MAKE)/'d objs/Makefile
sed -i -e '/cd ..\/libressl-2.8.3/'d objs/Makefile
sed -i -e '/no-shared no-threads/'d objs/Makefile
sed -i -e '/&& $(MAKE) /'d objs/Makefile

sed -i -e "s/-I ..\/libressl-2.8.3\/.openssl\/include/-I ..\/libressl-2.8.3\/include/g" objs/Makefile

sed -i -e "s/..\/libressl-2.8.3\/.openssl\/lib\/libssl.a ..\/libressl-2.8.3\/.openssl\/lib\/libcrypto.a/..\/libressl-2.8.3\/crypto\/libzerocache.a -lsgx_urts -lsgx_uae_service/g" objs/Makefile

make -j8
make install

ln -s ../libressl-2.8.3/crypto/enclave.signed.so
