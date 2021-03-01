./configure --prefix=./install --with-http_ssl_module --with-threads --with-file-aio --without-pcre --with-http_v2_module --without-http_rewrite_module
make -j8
make install
