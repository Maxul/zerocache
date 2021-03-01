# Copyright 2018 - 2019 TEEX.Inc

CRYPTO_SFILES = aes/aes-elf-x86_64.S aes/bsaes-elf-x86_64.S \
	aes/vpaes-elf-x86_64.S aes/aesni-elf-x86_64.S \
	aes/aesni-sha1-elf-x86_64.S bn/modexp512-elf-x86_64.S \
	bn/mont-elf-x86_64.S bn/mont5-elf-x86_64.S \
	bn/gf2m-elf-x86_64.S camellia/cmll-elf-x86_64.S \
	md5/md5-elf-x86_64.S modes/ghash-elf-x86_64.S \
	rc4/rc4-elf-x86_64.S rc4/rc4-md5-elf-x86_64.S \
	sha/sha1-elf-x86_64.S sha/sha256-elf-x86_64.S \
	sha/sha512-elf-x86_64.S whrlpool/wp-elf-x86_64.S

LIBCRYPTO_SFILES := $(CRYPTO_SFILES:.S=.o)

CRYPTO_CFILES = cpt_err.c cryptlib.c \
	crypto_init.c cversion.c ex_data.c malloc-wrapper.c mem_clr.c \
	mem_dbg.c o_init.c o_str.c o_time.c aes/aes_cfb.c \
	aes/aes_ctr.c aes/aes_ecb.c aes/aes_ige.c aes/aes_misc.c \
	aes/aes_ofb.c aes/aes_wrap.c asn1/a_bitstr.c asn1/a_bool.c \
	asn1/a_bytes.c asn1/a_d2i_fp.c asn1/a_digest.c asn1/a_dup.c \
	asn1/a_enum.c asn1/a_i2d_fp.c asn1/a_int.c asn1/a_mbstr.c \
	asn1/a_object.c asn1/a_octet.c asn1/a_print.c asn1/a_set.c \
	asn1/a_sign.c asn1/a_strex.c asn1/a_strnid.c asn1/a_time.c \
	asn1/a_time_tm.c asn1/a_type.c asn1/a_utf8.c asn1/a_verify.c \
	asn1/ameth_lib.c asn1/asn1_err.c asn1/asn1_gen.c \
	asn1/asn1_lib.c asn1/asn1_par.c asn1/asn_mime.c \
	asn1/asn_moid.c asn1/asn_pack.c asn1/bio_asn1.c \
	asn1/bio_ndef.c asn1/d2i_pr.c asn1/d2i_pu.c asn1/evp_asn1.c \
	asn1/f_enum.c asn1/f_int.c asn1/f_string.c asn1/i2d_pr.c \
	asn1/i2d_pu.c asn1/n_pkey.c asn1/nsseq.c asn1/p5_pbe.c \
	asn1/p5_pbev2.c asn1/p8_pkey.c asn1/t_bitst.c asn1/t_crl.c \
	asn1/t_pkey.c asn1/t_req.c asn1/t_spki.c asn1/t_x509.c \
	asn1/t_x509a.c asn1/tasn_dec.c asn1/tasn_enc.c asn1/tasn_fre.c \
	asn1/tasn_new.c asn1/tasn_prn.c asn1/tasn_typ.c \
	asn1/tasn_utl.c asn1/x_algor.c asn1/x_attrib.c asn1/x_bignum.c \
	asn1/x_crl.c asn1/x_exten.c asn1/x_info.c asn1/x_long.c \
	asn1/x_name.c asn1/x_nx509.c asn1/x_pkey.c asn1/x_pubkey.c \
	asn1/x_req.c asn1/x_sig.c asn1/x_spki.c asn1/x_val.c \
	asn1/x_x509.c asn1/x_x509a.c bf/bf_cfb64.c bf/bf_ecb.c \
	bf/bf_enc.c bf/bf_ofb64.c bf/bf_skey.c bio/b_dump.c \
	bio/b_posix.c bio/b_print.c bio/b_sock.c \
	bio/bf_buff.c bio/bf_nbio.c bio/bf_null.c bio/bio_cb.c \
	bio/bio_err.c bio/bio_lib.c bio/bio_meth.c bio/bss_acpt.c \
	bio/bss_bio.c bio/bss_conn.c bio/bss_dgram.c bio/bss_fd.c \
	bio/bss_file.c bio/bss_log.c bio/bss_mem.c bio/bss_null.c \
	bio/bss_sock.c bn/bn_add.c bn/bn_asm.c bn/bn_blind.c \
	bn/bn_const.c bn/bn_ctx.c bn/bn_depr.c bn/bn_div.c bn/bn_err.c \
	bn/bn_exp.c bn/bn_exp2.c bn/bn_gcd.c bn/bn_gf2m.c bn/bn_kron.c \
	bn/bn_lib.c bn/bn_mod.c bn/bn_mont.c bn/bn_mpi.c bn/bn_mul.c \
	bn/bn_nist.c bn/bn_prime.c bn/bn_print.c bn/bn_rand.c \
	bn/bn_recp.c bn/bn_shift.c bn/bn_sqr.c bn/bn_sqrt.c \
	bn/bn_word.c bn/bn_x931p.c buffer/buf_err.c buffer/buf_str.c \
	buffer/buffer.c camellia/cmll_cfb.c camellia/cmll_ctr.c \
	camellia/cmll_ecb.c camellia/cmll_misc.c camellia/cmll_ofb.c \
	cast/c_cfb64.c cast/c_ecb.c cast/c_enc.c cast/c_ofb64.c \
	cast/c_skey.c chacha/chacha.c cmac/cm_ameth.c cmac/cm_pmeth.c \
	cmac/cmac.c comp/c_rle.c comp/c_zlib.c comp/comp_err.c \
	comp/comp_lib.c conf/conf_api.c conf/conf_def.c \
	conf/conf_err.c conf/conf_lib.c conf/conf_mall.c \
	conf/conf_mod.c conf/conf_sap.c \
	curve25519/curve25519-generic.c curve25519/curve25519.c \
	des/cbc_cksm.c des/cbc_enc.c des/cfb64ede.c des/cfb64enc.c \
	des/cfb_enc.c des/des_enc.c des/ecb3_enc.c des/ecb_enc.c \
	des/ede_cbcm_enc.c des/enc_read.c des/enc_writ.c des/fcrypt.c \
	des/fcrypt_b.c des/ofb64ede.c des/ofb64enc.c des/ofb_enc.c \
	des/pcbc_enc.c des/qud_cksm.c des/rand_key.c des/set_key.c \
	des/str2key.c des/xcbc_enc.c dh/dh_ameth.c dh/dh_asn1.c \
	dh/dh_check.c dh/dh_depr.c dh/dh_err.c dh/dh_gen.c dh/dh_key.c \
	dh/dh_lib.c dh/dh_pmeth.c dh/dh_prn.c dsa/dsa_ameth.c \
	dsa/dsa_asn1.c dsa/dsa_depr.c dsa/dsa_err.c dsa/dsa_gen.c \
	dsa/dsa_key.c dsa/dsa_lib.c dsa/dsa_meth.c dsa/dsa_ossl.c \
	dsa/dsa_pmeth.c dsa/dsa_prn.c dsa/dsa_sign.c dsa/dsa_vrf.c \
	dso/dso_dlfcn.c dso/dso_err.c dso/dso_lib.c dso/dso_null.c \
	dso/dso_openssl.c ec/ec2_mult.c ec/ec2_oct.c ec/ec2_smpl.c \
	ec/ec_ameth.c ec/ec_asn1.c ec/ec_check.c ec/ec_curve.c \
	ec/ec_cvt.c ec/ec_err.c ec/ec_key.c ec/ec_lib.c ec/ec_mult.c \
	ec/ec_oct.c ec/ec_pmeth.c ec/ec_print.c ec/eck_prn.c \
	ec/ecp_mont.c ec/ecp_nist.c ec/ecp_oct.c ec/ecp_smpl.c \
	ecdh/ech_err.c ecdh/ech_key.c ecdh/ech_lib.c ecdsa/ecs_asn1.c \
	ecdsa/ecs_err.c ecdsa/ecs_lib.c ecdsa/ecs_ossl.c \
	ecdsa/ecs_sign.c ecdsa/ecs_vrf.c engine/eng_all.c \
	engine/eng_cnf.c engine/eng_ctrl.c engine/eng_dyn.c \
	engine/eng_err.c engine/eng_fat.c engine/eng_init.c \
	engine/eng_lib.c engine/eng_list.c engine/eng_openssl.c \
	engine/eng_pkey.c engine/eng_table.c engine/tb_asnmth.c \
	engine/tb_cipher.c engine/tb_dh.c engine/tb_digest.c \
	engine/tb_dsa.c engine/tb_ecdh.c engine/tb_ecdsa.c \
	engine/tb_pkmeth.c engine/tb_rand.c engine/tb_rsa.c \
	engine/tb_store.c err/err.c err/err_all.c err/err_prn.c \
	evp/bio_b64.c evp/bio_enc.c evp/bio_md.c evp/c_all.c \
	evp/digest.c evp/e_aes.c evp/e_aes_cbc_hmac_sha1.c evp/e_bf.c \
	evp/e_camellia.c evp/e_cast.c evp/e_chacha.c \
	evp/e_chacha20poly1305.c evp/e_des.c evp/e_des3.c \
	evp/e_gost2814789.c evp/e_idea.c evp/e_null.c evp/e_old.c \
	evp/e_rc2.c evp/e_rc4.c evp/e_rc4_hmac_md5.c evp/e_xcbc_d.c \
	evp/encode.c evp/evp_aead.c evp/evp_enc.c evp/evp_err.c \
	evp/evp_key.c evp/evp_lib.c evp/evp_pbe.c evp/evp_pkey.c \
	evp/m_dss.c evp/m_dss1.c evp/m_ecdsa.c evp/m_gost2814789.c \
	evp/m_gostr341194.c evp/m_md4.c evp/m_md5.c evp/m_md5_sha1.c \
	evp/m_null.c evp/m_ripemd.c evp/m_sha1.c evp/m_sigver.c \
	evp/m_streebog.c evp/m_wp.c evp/names.c evp/p5_crpt.c \
	evp/p5_crpt2.c evp/p_dec.c evp/p_enc.c evp/p_lib.c \
	evp/p_open.c evp/p_seal.c evp/p_sign.c evp/p_verify.c \
	evp/pmeth_fn.c evp/pmeth_gn.c evp/pmeth_lib.c \
	gost/gost2814789.c gost/gost89_keywrap.c gost/gost89_params.c \
	gost/gost89imit_ameth.c gost/gost89imit_pmeth.c \
	gost/gost_asn1.c gost/gost_err.c gost/gostr341001.c \
	gost/gostr341001_ameth.c gost/gostr341001_key.c \
	gost/gostr341001_params.c gost/gostr341001_pmeth.c \
	gost/gostr341194.c gost/streebog.c hkdf/hkdf.c hmac/hm_ameth.c \
	hmac/hm_pmeth.c hmac/hmac.c idea/i_cbc.c idea/i_cfb64.c \
	idea/i_ecb.c idea/i_ofb64.c idea/i_skey.c lhash/lh_stats.c \
	lhash/lhash.c md4/md4_dgst.c md4/md4_one.c md5/md5_dgst.c \
	md5/md5_one.c modes/cbc128.c modes/ccm128.c modes/cfb128.c \
	modes/ctr128.c modes/cts128.c modes/gcm128.c modes/ofb128.c \
	modes/xts128.c objects/o_names.c objects/obj_dat.c \
	objects/obj_err.c objects/obj_lib.c objects/obj_xref.c \
	ocsp/ocsp_asn.c ocsp/ocsp_cl.c ocsp/ocsp_err.c ocsp/ocsp_ext.c \
	ocsp/ocsp_ht.c ocsp/ocsp_lib.c ocsp/ocsp_prn.c ocsp/ocsp_srv.c \
	ocsp/ocsp_vfy.c pem/pem_all.c pem/pem_err.c pem/pem_info.c \
	pem/pem_lib.c pem/pem_oth.c pem/pem_pk8.c pem/pem_pkey.c \
	pem/pem_seal.c pem/pem_sign.c pem/pem_x509.c pem/pem_xaux.c \
	pem/pvkfmt.c pkcs12/p12_add.c pkcs12/p12_asn.c \
	pkcs12/p12_attr.c pkcs12/p12_crpt.c pkcs12/p12_crt.c \
	pkcs12/p12_decr.c pkcs12/p12_init.c pkcs12/p12_key.c \
	pkcs12/p12_kiss.c pkcs12/p12_mutl.c pkcs12/p12_npas.c \
	pkcs12/p12_p8d.c pkcs12/p12_p8e.c pkcs12/p12_utl.c \
	pkcs12/pk12err.c pkcs7/bio_pk7.c pkcs7/pk7_asn1.c \
	pkcs7/pk7_attr.c pkcs7/pk7_doit.c pkcs7/pk7_lib.c \
	pkcs7/pk7_mime.c pkcs7/pk7_smime.c pkcs7/pkcs7err.c \
	poly1305/poly1305.c rand/rand_err.c rand/rand_lib.c \
	rand/randfile.c rc2/rc2_cbc.c rc2/rc2_ecb.c rc2/rc2_skey.c \
	rc2/rc2cfb64.c rc2/rc2ofb64.c ripemd/rmd_dgst.c \
	ripemd/rmd_one.c rsa/rsa_ameth.c rsa/rsa_asn1.c rsa/rsa_chk.c \
	rsa/rsa_crpt.c rsa/rsa_depr.c rsa/rsa_eay.c rsa/rsa_err.c \
	rsa/rsa_gen.c rsa/rsa_lib.c rsa/rsa_meth.c rsa/rsa_none.c \
	rsa/rsa_oaep.c rsa/rsa_pk1.c rsa/rsa_pmeth.c rsa/rsa_prn.c \
	rsa/rsa_pss.c rsa/rsa_saos.c rsa/rsa_sign.c rsa/rsa_x931.c \
	sha/sha1_one.c sha/sha1dgst.c sha/sha256.c sha/sha512.c \
	stack/stack.c ts/ts_asn1.c ts/ts_conf.c ts/ts_err.c \
	ts/ts_lib.c ts/ts_req_print.c ts/ts_req_utils.c \
	ts/ts_rsp_print.c ts/ts_rsp_sign.c ts/ts_rsp_utils.c \
	ts/ts_rsp_verify.c ts/ts_verify_ctx.c txt_db/txt_db.c \
	ui/ui_err.c ui/ui_lib.c ui/ui_openssl.c \
	ui/ui_util.c whrlpool/wp_dgst.c x509/by_dir.c x509/by_file.c \
	x509/by_mem.c x509/x509_att.c x509/x509_cmp.c x509/x509_d2.c \
	x509/x509_def.c x509/x509_err.c x509/x509_ext.c x509/x509_lu.c \
	x509/x509_obj.c x509/x509_r2x.c x509/x509_req.c \
	x509/x509_set.c x509/x509_trs.c x509/x509_txt.c x509/x509_v3.c \
	x509/x509_vfy.c x509/x509_vpm.c x509/x509cset.c \
	x509/x509name.c x509/x509rset.c x509/x509spki.c \
	x509/x509type.c x509/x_all.c x509v3/pcy_cache.c \
	x509v3/pcy_data.c x509v3/pcy_lib.c x509v3/pcy_map.c \
	x509v3/pcy_node.c x509v3/pcy_tree.c x509v3/v3_akey.c \
	x509v3/v3_akeya.c x509v3/v3_alt.c x509v3/v3_bcons.c \
	x509v3/v3_bitst.c x509v3/v3_conf.c x509v3/v3_cpols.c \
	x509v3/v3_crld.c x509v3/v3_enum.c x509v3/v3_extku.c \
	x509v3/v3_genn.c x509v3/v3_ia5.c x509v3/v3_info.c \
	x509v3/v3_int.c x509v3/v3_lib.c x509v3/v3_ncons.c \
	x509v3/v3_ocsp.c x509v3/v3_pci.c x509v3/v3_pcia.c \
	x509v3/v3_pcons.c x509v3/v3_pku.c x509v3/v3_pmaps.c \
	x509v3/v3_prn.c x509v3/v3_purp.c x509v3/v3_skey.c \
	x509v3/v3_sxnet.c x509v3/v3_utl.c x509v3/v3err.c

LIBCRYPTO_CFILES := $(CRYPTO_CFILES:.c=.o)

SSL_CFILES := $(wildcard ../ssl/*.c)
LIBSSL_CFILES := $(SSL_CFILES:.c=.o)

COMPAT_FILES = compat/strlcat.o \
                    compat/strsep.o \
					compat/strlcpy.o \
					compat/reallocarray.o \
					compat/timingsafe_memcmp.o \
					compat/timingsafe_bcmp.o \
					compat/freezero.o \
					compat/recallocarray.o \
					compat/explicit_bzero.o

ZERO_CACHE_TRUSTED_CFILES = $(wildcard ZeroCache/enclave/*.c)
ZERO_CACHE_TRUSTED_MODULE := $(ZERO_CACHE_TRUSTED_CFILES:.c=.o)

ZERO_CACHE_UNTRUSTED_CFILES = $(wildcard ZeroCache/*.c)
ZERO_CACHE_UNTRUSTED_MODULE := $(ZERO_CACHE_UNTRUSTED_CFILES:.c=.o)

################################################################################

top_srcdir = ..

CC = gcc
CXX = g++

CCASFLAGS = -g -O -Wall -Werror -std=gnu99 -fno-strict-aliasing -fno-strict-overflow -U_FORTIFY_SOURCE -fstack-protector-all -DHAVE_GNU_STACK -Wno-implicit-function-declaration -w -fpermissive

CFLAGS = -g -O -Wall -Werror -std=gnu99 -fno-strict-aliasing -fno-strict-overflow -U_FORTIFY_SOURCE -fstack-protector-all -DHAVE_GNU_STACK -Wno-pointer-sign -w -fpermissive

CXXFLAGS = -g -O -Wall -Werror -std=c++11 -fno-strict-aliasing -fno-strict-overflow -U_FORTIFY_SOURCE -fstack-protector-all -DHAVE_GNU_STACK -w -fpermissive
CPPFLAGS = -DOPENSSLDIR=\"/etc/ssl\" \
    -DAES_ASM -DBSAES_ASM \
	-DVPAES_ASM -DOPENSSL_IA32_SSE2 \
	-DOPENSSL_BN_ASM_MONT \
	-DOPENSSL_BN_ASM_MONT5 \
	-DOPENSSL_BN_ASM_GF2m -DMD5_ASM \
	-DGHASH_ASM -DRSA_ASM -DSHA1_ASM \
	-DSHA256_ASM -DSHA512_ASM \
	-DWHIRLPOOL_ASM -DOPENSSL_CPUID_OBJ \
	-D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE -D_GNU_SOURCE \
	-DLIBRESSL_INTERNAL -DOPENSSL_NO_HW_PADLOCK -D__BEGIN_HIDDEN_DECLS= -D__END_HIDDEN_DECLS= \
    -DCOMPILE_WITH_INTEL_SGX

DEFS = -DPACKAGE_NAME=\"libressl\" -DPACKAGE_TARNAME=\"libressl\" -DPACKAGE_VERSION=\"2.8.3\" -DPACKAGE_STRING=\"libressl\ 2.8.3\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"libressl\" -DVERSION=\"2.8.3\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_DLFCN_H=1 -DLT_OBJDIR=\".libs/\" -DHAVE_SYMLINK=1 -DHAVE_ERR_H=1 -DHAVE_ASPRINTF=1 -DHAVE_MEMMEM=1 -DHAVE_STRNDUP=1 -DHAVE_STRNLEN=1 -DHAVE_STRSEP=1 -DHAVE_TIMEGM=1 -DHAVE_ACCEPT4=1 -DHAVE_PIPE2=1 -DHAVE_POLL=1 -DHAVE_SOCKETPAIR=1 -DHAVE_GETAUXVAL=1 -DHAVE_GETAUXVAL=1 -DHAVE_DL_ITERATE_PHDR=1 -DHAVE_CLOCK_GETTIME=1 -DHAVE_VA_COPY=1 -DHAVE___VA_COPY=1 -DHAS_GNU_WARNING_LONG=1 -DSIZEOF_TIME_T=8 -DHAVE_CLOCK_GETTIME

INCLUDE = -I. -I${top_srcdir}/include -I${top_srcdir}/include/compat -I${top_srcdir}/crypto/asn1 -I${top_srcdir}/crypto/evp -I${top_srcdir}/crypto/modes -I${top_srcdir}/crypto -I${top_srcdir}/crypto/bn -I${top_srcdir}/include/openssl -IZeroCache/include

LDFLAGS = -Wl,-z,relro -Wl,-z,now

########## Intel SGX ############

##### Parameters #####

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

ifeq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
else
	Urts_Library_Name := sgx_urts_sim
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

Enclave_Config_File := ZeroCache/enclave/enclave.config.xml

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) 

ifeq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service
else
	App_Link_Flags += -lsgx_uae_service_sim
endif

#################################

all: link signed_enclave enclave_u.o

########## Intel SGX ############

##### App Objects #####

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -Wno-implicit-function-declaration -Wformat-security -Waddress -Wundef -Wshadow

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

enclave_u.c: $(SGX_EDGER8R) ZeroCache/enclave/enclave.edl
	@$(SGX_EDGER8R) --untrusted enclave.edl --search-path ./ZeroCache/enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave_u.o: enclave_u.c
	@$(CC) $(App_C_Flags) -I ./ZeroCache/include -I../include -I$(SGX_SDK)/include -c $< -o $@
	@echo "CC   <=  $<"

zc_apis.o: ZeroCache/zc_apis.c
	@$(CC) $(App_C_Flags) -I ./ZeroCache/include -I../include -I$(SGX_SDK)/include -c $< -o $@
	@echo "CC   <=  $<"

zc_dumb.o: ZeroCache/zc_dumb.c
	@$(CC) $(App_C_Flags) -I ./ZeroCache/include -I../include -I$(SGX_SDK)/include -c $< -o $@
	@echo "CC   <=  $<"

u_ocalls.o: ZeroCache/u_ocalls.c
	@$(CC) $(App_C_Flags) -I ./ZeroCache/include -I../include -fPIC -DPIC -Werror -c $< -o $@
	@echo "CC   <=  $<"

##### Enclave Objects #####

Enclave_Include_Paths := -I. -I../include -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) -maes -msse4
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_tswitchless -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcmalloc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=ZeroCache/enclave/enclave.lds

enclave_t.c: $(SGX_EDGER8R) ZeroCache/enclave/enclave.edl
	@$(SGX_EDGER8R) --trusted ZeroCache/enclave/enclave.edl --search-path . --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave_t.o: enclave_t.c
	@$(CC) $(Enclave_C_Flags) -I ./ZeroCache/include -DDEFINE_TIME_STRUCT -c $< -o $@
	@echo "CC   <=  $<"

#################################

%.o: %.s
	@$(CC) $(CCASFLAGS) -c $< -fPIC -DPIC -o $@

%.o: %.S
	$(eval srcbasefile=$(basename $@))
	$(eval dstbasefile=$(basename $(notdir $@)))
	@$(eval maindir=$(dir $@))
	@$(CC) $(DEFS) $(CPPFLAGS) $(INCLUDE) $(CCASFLAGS) $(Enclave_C_Flags) -I$(SGX_SDK)/include -fPIC -DPIC -c -o $(maindir)$(dstbasefile).o $(srcbasefile).S
	@echo "CC  <=  $<"

%.o: %.cpp
	$(eval srcbasefile=$(basename $@))
	$(eval dstbasefile=$(basename $(notdir $@)))
	$(eval maindir=$(dir $@))
	$(CXX) $(DEFS) $(INCLUDE) $(CPPFLAGS) $(CXXFLAGS) $(Enclave_Cpp_Flags) -I$(SGX_SDK)/include -fPIC -DPIC -c -o $(maindir)$(dstbasefile).o $(maindir)$(dstbasefile).cpp
	@echo "CXX  <=  $<"

%.o: %.c
	$(eval srcbasefile=$(basename $@))
	$(eval dstbasefile=$(basename $(notdir $@)))
	$(eval maindir=$(dir $@))
	@$(CC) $(DEFS) $(INCLUDE) $(CPPFLAGS) $(CFLAGS) -I$(SGX_SDK)/include -E -o $(maindir)$(dstbasefile).i $(srcbasefile).c
	@$(CC) $(DEFS) $(INCLUDE) $(CPPFLAGS) $(CFLAGS) $(Enclave_C_Flags) -I$(SGX_SDK)/include -fPIC -DPIC -c -o $(maindir)$(dstbasefile).o $(maindir)$(dstbasefile).i
	@echo "CC  <=  $<"

libcrypto_sfiles: $(LIBCRYPTO_SFILES)

libcrypto_cfiles: $(LIBCRYPTO_CFILES)

libssl_cfiles: $(LIBSSL_CFILES)

compat: $(COMPAT_FILES)

zero_cache: $(ZERO_CACHE_TRUSTED_MODULE)

#################################

enclave: enclave_t.o libcrypto_sfiles libcrypto_cfiles libssl_cfiles compat zero_cache
	@$(CXX) enclave_t.o $(LIBCRYPTO_SFILES) $(LIBCRYPTO_CFILES) $(LIBSSL_CFILES) $(COMPAT_FILES) $(AUDITORS_UTILS) $(ZERO_CACHE_TRUSTED_MODULE) -o $(Enclave_Name) $(Enclave_Link_Flags)
	@echo "LINK =>  $(Enclave_Name)"

signed_enclave: enclave
	@$(SGX_ENCLAVE_SIGNER) sign -key ZeroCache/enclave/enclave_private.pem -enclave $(Enclave_Name) -out $(Signed_Enclave_Name) -config $(Enclave_Config_File)
	@echo "SIGN =>  $(Signed_Enclave_Name)"
	@rm $(Enclave_Name)
	find .. -iname "*\.i" -delete

#################################

link: enclave_u.o $(ZERO_CACHE_UNTRUSTED_MODULE)
	ar cru libzerocache.a enclave_u.o $(ZERO_CACHE_UNTRUSTED_MODULE)
	$(CC) -fPIC -shared -o libzerocache.so enclave_u.o $(ZERO_CACHE_UNTRUSTED_MODULE) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) 

clean:
	rm -rf \.libs
	rm -rf *\.la
	find . -iname "enclave_u.?" -delete
	find . -iname "enclave_t.?" -delete
	find . -iname "$(Enclave_Name)" -delete
	find . -iname "$(Signed_Enclave_Name)" -delete
	find . -iname "*\.dirstamp" -delete
	find . -iname "*\.o" -delete
	find $(top_srcdir)/ssl -iname "*\.o" -delete
	find . -iname "*\.i" -delete
	find $(top_srcdir)/ssl -iname "*\.i" -delete
	find . -iname "*\.deps" -delete
	find . -iname "*\.libs" -delete
	find . -iname "libzerocache.a" -delete
	find . -iname "libzerocache.so" -delete

