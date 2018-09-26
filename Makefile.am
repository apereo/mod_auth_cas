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

baseclean:  maintainer-clean
	rm -f Makefile.in configure aclocal.m4 config.guess config.h.in~ config.h.in config.sub depcomp install-sh ltmain.sh missing compile m4/libtool.m4 m4/lt~obsolete.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 test-driver src/Makefile.in src/*.slo tests/Makefile.in src/*.gcda src/*.gcno tests/core.*

	
dist: ${DISTBALL}

${DISTBALL}:
	rm -f ${DISTBALL}
	mkdir -p ${DISTDIR}
	cp --parents ${DISTFILES} ${DISTDIR}
	tar -czvf ${DISTBALL} ${DISTDIR}

pretty:
	cd src && $(MAKE) $@
