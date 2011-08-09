AM_CFLAGS = @CPPFLAGS@ @CFLAGS@ @LIBCURL_CPPFLAGS@ \
@APR_CPPFLAGS@ \
@APR_CPPFLAGS@ \
@APR_INCLUDES@ \
@APACHE_INCLUDES@ \
-D_LARGEFILE64_SOURCE @LIBS@ @LIBCURL@

AM_LDFLAGS= @LDFLAGS@
TESTS=
if CHECK
TESTS += check_mac
check_PROGRAMS = check_mac
check_mac_SOURCES = ap_stubs.c curl_stubs.c openssl_stubs.c ../src/mod_auth_cas.c mod_auth_cas_test.c
check_mac_LDADD = -lcheck -lapr-1 -laprutil-1
check_mac_CFLAGS = @CHECK_CFLAGS@ ${AM_CFLAGS}
check_mac_LDFLAGS = @CHECK_LDFLAGS@ ${AM_LDFLAGS}
endif
