#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([mod_auth_cas], [1.0.10], [mod-auth-cas-dev@lists.jasig.org])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_CONFIG_HEADER([config.h])

AC_LIBTOOL_DLOPEN
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_GNU_SOURCE
AC_ISC_POSIX
AC_PROG_LIBTOOL
AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)

AM_INIT_AUTOMAKE([foreign 1.7])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

#### Locate APXS
## First, check --with-apxs
AC_DEFUN([CHECK_APXS],[
    AC_MSG_CHECKING(for Apache apxs)
    AC_ARG_WITH(
        apxs,
        [  --with-apxs=FILE        location of the Apache apxs utility],  
    [if test -x "${with_apxs}" ; then
        apxs_found="${with_apxs}"
            AC_MSG_RESULT([$apxs_found])
    fi]
        ,
        [ 
        APXS_NAMES=apxs2
        if test "${apache_version}"="2"; then
            APXS_NAMES="$APXS_NAMES apxs2"
        fi
        for apxs_file in ${APXS_NAMES}; do 
            for apxs_path in bin sbin; do 
                 if test -x "${apache_base}"/"${apxs_path}"/"${apxs_file}"; then
                        apxs_found="${apache_base}"/"${apxs_path}"/"${apxs_file}" 
                        break 2
                  fi
            done
        done
        if test x"$apxs_found" = x; then
            AC_PATH_PROGS(with_apxs, apxs2)
            if test "${with_apxs+set}" = set ; then
                apxs_found="${with_apxs}"
            fi
        fi
        if test x"${apxs_found}" = x; then
            AC_MSG_ERROR([Could not find apxs.  apxs must be in your PATH or you must specify the location of the apxs script using --with-apxs])
        else
            AC_MSG_RESULT([$apxs_found])
        fi
       ]
    )
    if test "${apxs_found+set}" = set ; then
        dnl At this point we already have apr sorted out
        export PATH=$PATH:`dirname $apxs_found`
        APXS_CPPFLAGS=`${apxs_found} -q CFLAGS`
        AC_SUBST(APXS_CPPFLAGS)
        APXS_LDFLAGS=`${apxs_found} -q LDFLAGS_SHLIB`
        AC_SUBST(APXS_LDFLAGS)
        APXS_LIBS=`${apxs_found} -q LIBS_SHLIB`
        AC_SUBST(APXS_LIBS)
        APXS_INCLUDES=-I`${apxs_found} -q INCLUDEDIR`
        AC_SUBST(APXS_INCLUDES)
        APXS_CPPFLAGS_SHLIB=`${apxs_found} -q CFLAGS_SHLIB`
        AC_SUBST(APXS_CPPFLAGS_SHLIB)
        APXS_LD_SHLIB=`${apxs_found} -q LD_SHLIB`
        AC_SUBST(APXS_LD_SHLIB)
        APXS_LIBEXECDIR=`${apxs_found} -q LIBEXECDIR`
        AC_SUBST(APXS_LIBEXECDIR)
        APXS_SYSCONFDIR=`${apxs_found} -q SYSCONFDIR`
        AC_SUBST(APXS_SYSCONFDIR)
        APXS_PREFIX=`${apxs_found} -q PREFIX`
        AC_SUBST(APXS_PREFIX)
    else 
        AC_MSG_ERROR([Could not find apxs.  apxs must be in your PATH or you must specify the location of the apxs script using --with-apxs])
    fi
])

CHECK_APXS

if test -f "$WITH_APXS" && test -x "$WITH_APXS"
then
	APXS=$WITH_APXS
else
	AC_PATH_PROGS([APXS],[apxs apxs2])
fi

if test "$APXS"
then
	AC_MSG_NOTICE([apxs found at $APXS])
	AC_SUBST([APXS])
else
	AC_MSG_FAILURE([apxs not found])
fi

#### Done locating APXS

AC_DEFUN([APACHE_INCL],[
  AC_ARG_WITH(
    apache_include,
    [  --with-apache-include[=DIR]     Apache server directory],
     [APACHE_INCLUDES="${with_apache_include}"]
    ,[APACHE_INCLUDES="${APXS_INCLUDES}"]
  )
    AC_SUBST(APACHE_INCLUDES)
])
APACHE_INCL

AC_DEFUN([APR_HANDLING],[
  AC_MSG_CHECKING(for Apache apr)
  AC_ARG_WITH(
   apr_config,
    [  --with-apr-config=FILE     apr portable apr-1-config path],
     [if test -x "${with_apr_config}"; then
         apr_found="${with_apr_config}"
     fi]
         ,
    [if test -x "${apache_base}/bin/apr-1-config" ; then
         apr_found="${apache_base}/bin/apr-1-config"
    elif test -x "/usr/bin/apr-1-config" ; then
         apr_found="/usr/bin/apr-1-config"
    elif test -x "${apache_base}/sbin/apr-1-config" ; then
         apr_found="${apache_base}/sbin/apr-1-config"
    elif test "${apache_base+set}" = set; then
        AC_PATH_PROGS(with_apr_config, apr-1-config)
        if test "${with_apr_config+set}" = set ; then
            apr_found="${with_apr_config}"
        fi
    else
        AC_MSG_ERROR( Specify the apr-1-config path using --with-apr-config, 1)
    fi]
)
    if test "${apr_found+set}" = set ; then
            AC_MSG_RESULT([$apr_found])
        dnl At this point we already have apr sorted out
        dnl It actually calls another script, so the PATH needs to be set.
        export PATH=$PATH:`dirname ${apr_found}`
        APR_CPPFLAGS=`${apr_found} --cppflags`
        AC_SUBST(APR_CPPFLAGS)
        APR_INCLUDES=`${apr_found} --includes`
        AC_SUBST(APR_INCLUDES)
        APR_LDFLAGS=`${apr_found} --link-libtool --libs`
        AC_SUBST(APR_LDFLAGS)
    else
        AC_MSG_ERROR([Could not find apr-1-config. apr-1-config must be in your PATH or you must specify the location of the apr script using --with-apr-config])
    fi
])
APR_HANDLING

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

#### Find OpenSSL
AC_MSG_CHECKING([for --with-openssl])
AC_ARG_WITH(
	[openssl],
	[AS_HELP_STRING([--with-openssl],[/absolute/path/to/openssl-base])],
	[ LDFLAGS="$LDFLAGS -L$with_openssl/lib";
	  CPPLAGS="$CPPLAGS -I$with_openssl/include/";
	  LIBS="-lssl";
	  AC_MSG_RESULT([$with_openssl])
	],
	[AC_MSG_RESULT([no])]
)

AC_CHECK_LIB([crypto],[CRYPTO_new_ex_data], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_LIB([ssl],[SSL_library_init], [], [AC_MSG_ERROR([OpenSSL libraries required])])

AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/ssl.h openssl/err.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

#### Check for libcurl
LIBCURL_CHECK_CONFIG([yes],[],[],[AC_MSG_ERROR([libcurl development files required])])

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
