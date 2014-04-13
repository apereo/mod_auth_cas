
AM_CPPFLAGS = @INCLTDL@ @LIBCURL_CPPFLAGS@ -D_LARGEFILE64_SOURCE \
 @APXS_CPPFLAGS@ @APXS_INCLUDES@ @APR_CPPFLAGS@ @APR_INCLUDES@
AM_LIBS = @LIBCURL@ @APXS_LIBS@
AM_CFLAGS = @TEST_COVERAGE_CFLAGS@ 
AM_LDFLAGS = @APXS_LDFLAGS@ @APR_LDFLAGS@

TESTS=
if CHECK
TESTS += check_mac
check_PROGRAMS = check_mac
check_mac_SOURCES = ap_stubs.c curl_stubs.c openssl_stubs.c ../src/mod_auth_cas.c mod_auth_cas_test.c ../src/cas_saml_attr.c cas_saml_attr_test.c
check_mac_LDADD = -lcheck -lapr-1 -laprutil-1
check_mac_CFLAGS = @CHECK_CFLAGS@ ${AM_CFLAGS}
check_mac_LIBS = @CHECK_LIBS@ ${AM_LIBS}
check_mac_LDFLAGS = ${AM_LDFLAGS}
clean-local: clean-local-coverage
clean-local-coverage:
	rm -f *.gcda *.gcno
endif
