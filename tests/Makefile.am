
if TESTS
mactest_PROGRAMS = mactest

AM_CFLAGS = @CPPFLAGS@ @CFLAGS@ @LIBCURL_CPPFLAGS@ \
@APR_CPPFLAGS@ \
@APR_CPPFLAGS@ \
@APR_INCLUDES@ \
@APACHE_INCLUDES@ \
-D_LARGEFILE64_SOURCE @LIBS@ @LIBCURL@

#OLD, preserved just for notes
#@-D_LARGEFILE64_SOURCE @LIBS@ @LIBCURL@ @APR_LDFLAGS@ 

AM_LDFLAGS= @LDFLAGS@ 

mactest_SOURCES = ap_stubs.c curl_stubs.c openssl_stubs.c ../src/mod_auth_cas.c mod_auth_cas_test.c 
mactest_LDADD = -lcheck -lapr-1 -laprutil-1
mactestdir = @PREFIX@/tests

check-local: mactest
	@echo -e "\n\n"
	@echo -e "--------------------------------"
	@echo -e "Running mod_auth_cas testsuite.."
	@echo -e "\n\n"
	@./mactest
	@echo -e "\n\n"
	@echo -e "--------------------------------"
	@echo -e "\n\n"


endif
