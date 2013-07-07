ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = @INCLTDL@ @LIBCURL_CPPFLAGS@ -D_LARGEFILE64_SOURCE
AM_LIBS = @LIBCURL@
AM_CFLAGS = @TEST_COVERAGE_CFLAGS@ 

#Set a few distribution variables
DISTNAME=@PACKAGE_NAME@-@PACKAGE_VERSION@
DISTDIR=${DISTNAME}
DISTBALL=${DISTNAME}.tgz

BASEFILES=src/mod_auth_cas.c src/mod_auth_cas.h src/Makefile.in configure.ac config.h.in Makefile.in README README.win32 NOTES

DISTFILES=configure ${BASEFILES}

SUBDIRS = src tests

MAINTAINERCLEANFILES = Makefile.in configure aclocal.m4 config.guess config.h.in config.h.in~ \
        config.sub depcomp install-sh ltmain.sh missing init/*/Makefil{e,e.in} compile m4/l*

maintainer-clean-local:
	rm -rf autom4te.cache
	rm -rf ${MAINTAINERCLEANFILES}

clean:
	cd src && $(MAKE) $@
	cd tests && $(MAKE) $@
	rm -rf ${DISTDIR} ${DISTBALL}

distclean: clean
	cd src && $(MAKE) $@
	cd tests && $(MAKE) $@
	rm -rf config.h config.h.in~ config.log config.status autom4te.cache Makefile stamp-h1

baseclean: distclean
	rm -rf configure
	
dist: ${DISTBALL}

${DISTBALL}:
	rm -f ${DISTBALL}
	mkdir -p ${DISTDIR}
	cp --parents ${DISTFILES} ${DISTDIR}
	tar -czvf ${DISTBALL} ${DISTDIR}

pretty:
	cd src && $(MAKE) $@
