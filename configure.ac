#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([mod_auth_cas], [1.2], [cas-user@apereo.org])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE([disable])

AC_LIBTOOL_DLOPEN
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_GNU_SOURCE
AC_ISC_POSIX

AM_INIT_AUTOMAKE([foreign 1.7 subdir-objects])
#Backward compatability, allows for silent-rules in AM<1.11
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AX_CHECK_COMPILE_FLAG([-Wall],[CFLAGS="${CFLAGS} -Wall"])
AX_CHECK_COMPILE_FLAG([-Wextra],[CFLAGS="${CFLAGS} -Wextra"])
AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement],[CFLAGS="${CFLAGS} -Wdeclaration-after-statement"])
AX_CHECK_COMPILE_FLAG([-Wformat],[CFLAGS="${CFLAGS} -Wformat"])
AX_CHECK_COMPILE_FLAG([-Wformat-security],[CFLAGS="${CFLAGS} -Wformat-security"])
AX_CHECK_COMPILE_FLAG([-Wmissing-declarations],[CFLAGS="${CFLAGS} -Wmissing-declarations"])
AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter],[CFLAGS="${CFLAGS} -Wno-unused-parameter"])
AX_CHECK_COMPILE_FLAG([-Wpointer-arith],[CFLAGS="${CFLAGS} -Wpointer-arith"])
AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes],[CFLAGS="${CFLAGS} -Wstrict-prototypes"])

AC_PROG_LIBTOOL
AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)

#### Locate APXS
# Accept parameter of --with-apxs.  If not supplied, search path for apxs or apxs2
AC_ARG_WITH(
	[apxs],
	[AS_HELP_STRING([--with-apxs=PATH/TO/APXS],[location of the Apache apxs (or apxs2) utility, instead of searching path])],
	[AC_SUBST(APXS,$with_apxs)],
	[AC_PATH_PROGS(APXS,[apxs apxs2])])

AS_IF([ test "x$APXS" != "x" -a -x "$APXS" ],[
		AC_MSG_NOTICE([apxs found at $APXS])
        APXS_CPPFLAGS=`$APXS -q CFLAGS`
        AC_SUBST(APXS_CPPFLAGS)
        APXS_LDFLAGS=`$APXS -q LDFLAGS_SHLIB`
        AC_SUBST(APXS_LDFLAGS)
        APXS_LIBS=`$APXS -q LIBS_SHLIB`
        AC_SUBST(APXS_LIBS)
        APXS_INCLUDES=-I`$APXS -q INCLUDEDIR`
        AC_SUBST(APXS_INCLUDES)
        APXS_CPPFLAGS_SHLIB=`$APXS -q CFLAGS_SHLIB`
        AC_SUBST(APXS_CPPFLAGS_SHLIB)
        APXS_LD_SHLIB=`$APXS -q LD_SHLIB`
        AC_SUBST(APXS_LD_SHLIB)
        APXS_LIBEXECDIR=`$APXS -q LIBEXECDIR`
        AC_SUBST(APXS_LIBEXECDIR)
        APXS_SYSCONFDIR=`$APXS -q SYSCONFDIR`
        AC_SUBST(APXS_SYSCONFDIR)
        APXS_PREFIX=`$APXS -q PREFIX`
        AC_SUBST(APXS_PREFIX)
	],
	AC_MSG_FAILURE(["useable apxs not found - please use --with-apxs=/path/to/apxs"])
)
#### Done locating APXS

#### Locate APR
# Accept parameter of --with-apr.  If not supplied, search path for apr-1-config
AC_ARG_WITH(
	[apr],
	[AS_HELP_STRING([--with-apr=PATH/TO/APR-1-CONFIG],[location of the Apache APR config utility, instead of searching path])],
	[AC_SUBST(APR,$with_apr)],
	[AC_PATH_PROGS(APR,[apr-1-config])])

AS_IF([ test "x$APR" != "x" -a -x "$APR" ],[
		APR_CPPFLAGS=`$APR --cppflags`
        AC_SUBST(APR_CPPFLAGS)
        APR_INCLUDES=`$APR --includes`
        AC_SUBST(APR_INCLUDES)
        APR_LDFLAGS=`$APR --link-libtool --libs`
        AC_SUBST(APR_LDFLAGS)
	],
	AC_MSG_FAILURE(["useable apr-1-config not found - please use --with-apr=/path/to/apr-1-config"])
)

# Checks for libraries.


#### unit testing with Check
AC_ARG_WITH(
	[check],
	[AS_HELP_STRING([--with-check],[enable Check for unit testing @<:@default=no@:>@])],
	[],
	[with_check=no])

AS_IF(
	[test "x$with_check" != xno],
	[PKG_CHECK_MODULES(
		[CHECK],
		[check >= 0.9.4],
		[with_check=yes],
		[AC_MSG_ERROR([Could not find the Check library required to build test suite for mod_auth_cas])])
])

AM_CONDITIONAL([CHECK],[test x$with_check = xyes])

AC_ARG_ENABLE(
	[test-coverage],
	[AS_HELP_STRING([--enable-test-coverage],[Generate test coverage data @<:@default=no@:>@])],
	[],
	[enable_test_coverage=no])

AS_IF(
	[test "xenable_test_coverage" != xno],
	[AS_IF(
		[test "x$with_check" = xyes],
		[TEST_COVERAGE_CFLAGS="-fprofile-arcs -ftest-coverage"],
		[AC_MSG_WARN([Test coverage requested when not building tests (--with-check=no)])]
	)]
)

AC_SUBST(TEST_COVERAGE_CFLAGS)

#### Find OpenSSL

AX_CHECK_OPENSSL

AC_CHECK_LIB([crypto],[CRYPTO_new_ex_data], [], [AC_MSG_ERROR([OpenSSL libraries required])])

AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/ssl.h openssl/err.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

#### Check for libcurl
LIBCURL_CHECK_CONFIG([yes],[],[],[AC_MSG_ERROR([libcurl development files required])])

# Checks for libpcre
AC_CHECK_LIB([pcre], [pcre_compile], [], [AC_MSG_ERROR([libpcre required])])

# Checks for header files.
AC_CHECK_HEADERS([netdb.h stddef.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyname memset socket strcasecmp strchr strncasecmp strstr])

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 tests/Makefile])
AC_OUTPUT
