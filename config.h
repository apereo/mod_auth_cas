/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `gethostbyname' function. */
#define HAVE_GETHOSTBYNAME 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#define HAVE_LIBCRYPTO 1

/* Define to 1 if you have a functional curl library. */
#define HAVE_LIBCURL 1

/* Define to 1 if you have the `ssl' library (-lssl). */
#define HAVE_LIBSSL 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <openssl/crypto.h> header file. */
#define HAVE_OPENSSL_CRYPTO_H 1

/* Define to 1 if you have the <openssl/err.h> header file. */
#define HAVE_OPENSSL_ERR_H 1

/* Define to 1 if you have the <openssl/pem.h> header file. */
#define HAVE_OPENSSL_PEM_H 1

/* Define to 1 if you have the <openssl/ssl.h> header file. */
#define HAVE_OPENSSL_SSL_H 1

/* Define to 1 if you have the <openssl/x509.h> header file. */
#define HAVE_OPENSSL_X509_H 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Defined if libcurl supports AsynchDNS */
/* #undef LIBCURL_FEATURE_ASYNCHDNS */

/* Defined if libcurl supports IDN */
#define LIBCURL_FEATURE_IDN 1

/* Defined if libcurl supports IPv6 */
#define LIBCURL_FEATURE_IPV6 1

/* Defined if libcurl supports KRB4 */
/* #undef LIBCURL_FEATURE_KRB4 */

/* Defined if libcurl supports libz */
#define LIBCURL_FEATURE_LIBZ 1

/* Defined if libcurl supports NTLM */
#define LIBCURL_FEATURE_NTLM 1

/* Defined if libcurl supports SSL */
#define LIBCURL_FEATURE_SSL 1

/* Defined if libcurl supports SSPI */
/* #undef LIBCURL_FEATURE_SSPI */

/* Defined if libcurl supports DICT */
#define LIBCURL_PROTOCOL_DICT 1

/* Defined if libcurl supports FILE */
#define LIBCURL_PROTOCOL_FILE 1

/* Defined if libcurl supports FTP */
#define LIBCURL_PROTOCOL_FTP 1

/* Defined if libcurl supports FTPS */
#define LIBCURL_PROTOCOL_FTPS 1

/* Defined if libcurl supports HTTP */
#define LIBCURL_PROTOCOL_HTTP 1

/* Defined if libcurl supports HTTPS */
#define LIBCURL_PROTOCOL_HTTPS 1

/* Defined if libcurl supports IMAP */
#define LIBCURL_PROTOCOL_IMAP 1

/* Defined if libcurl supports LDAP */
#define LIBCURL_PROTOCOL_LDAP 1

/* Defined if libcurl supports POP3 */
#define LIBCURL_PROTOCOL_POP3 1

/* Defined if libcurl supports RTSP */
#define LIBCURL_PROTOCOL_RTSP 1

/* Defined if libcurl supports SMTP */
#define LIBCURL_PROTOCOL_SMTP 1

/* Defined if libcurl supports TELNET */
#define LIBCURL_PROTOCOL_TELNET 1

/* Defined if libcurl supports TFTP */
#define LIBCURL_PROTOCOL_TFTP 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Define to 1 if your C compiler doesn't accept -c and -o together. */
/* #undef NO_MINUS_C_MINUS_O */

/* Name of package */
#define PACKAGE "mod_auth_cas"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "modauthcas@gmail.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "mod_auth_cas"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "mod_auth_cas 1.0.10"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "mod_auth_cas"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0.10"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#define VERSION "1.0.10"

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define curl_free() as free() if our version of curl lacks curl_free. */
/* #undef curl_free */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */
