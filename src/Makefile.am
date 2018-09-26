
AM_CPPFLAGS = @INCLTDL@ @LIBCURL_CPPFLAGS@ -D_LARGEFILE64_SOURCE
AM_LIBS = @LIBCURL@
AM_CFLAGS = @TEST_COVERAGE_CFLAGS@ 

lib_LTLIBRARIES = mod_auth_cas.la

mod_auth_cas_la_LDFLAGS= -module ${AM_CFLAGS}

mod_auth_cas.la: mod_auth_cas.c mod_auth_cas.h cas_saml_attr.c cas_saml_attr.h
	@APXS@ -c ${LIBS} -Wc,"${CPPFLAGS} ${AM_CPPFLAGS} ${CFLAGS} ${AM_CFLAGS}" -Wl,"${AM_LDFLAGS} ${LDFLAGS} ${AM_LIBS} ${LIBS}" mod_auth_cas.c cas_saml_attr.c

install: mod_auth_cas.la
	if test ! -d ${DESTDIR}${APXS_LIBEXECDIR}; then mkdir -p ${DESTDIR}${APXS_LIBEXECDIR}; fi
	@APXS@ -i -S LIBEXECDIR=${DESTDIR}${APXS_LIBEXECDIR} mod_auth_cas.la

clean-local:
	rm -rf mod_auth_cas.slo mod_auth_cas.la mod_auth_cas.lo cas_saml_attr.lo cas_saml_attr.slo .libs
	
pretty:
	@indent --continuation-indentation1 --continue-at-parentheses --no-tabs --tab-size2 --indent-level2 --line-length80 --comment-line-length80 --space-after-for --space-after-if --space-after-while -v *.c *.h
