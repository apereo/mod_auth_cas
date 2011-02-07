#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([mod_auth_cas], [1.0.9.1], [modauthcas@gmail.com])
AC_CONFIG_SRCDIR([src/mod_auth_cas.c])
AC_CONFIG_HEADERS([config.h])

m4_include([libcurl.m4])

# Checks for programs.
AC_PROG_CC

#### Locate APXS
## First, check --with-apxs
AC_MSG_NOTICE([Locating apxs])
AC_MSG_CHECKING([for --with-apxs])
AC_ARG_WITH(
	[apxs],
	[AS_HELP_STRING([--with-apxs],[/absolute/path/to/apxs])],
	[WITH_APXS=$with_apxs],
	[WITH_APXS=no]
)
AC_MSG_RESULT([$WITH_APXS])

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

# Checks for libraries.
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
                 src/Makefile])
AC_OUTPUT
