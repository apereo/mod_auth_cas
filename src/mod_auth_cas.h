/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * mod_auth_cas.h
 * Apache CAS Authentication Module
 * Version 1.0.6
 *
 * Author:
 * Phil Ames       <phillip [dot] ames [at] uconn [dot] edu>
 * Designers:
 * Phil Ames       <phillip [dot] ames [at] uconn [dot] edu>
 * Matt Smith      <matt [dot] smith [at] uconn [dot] edu>
 */

#define CAS_DEFAULT_VERSION 2
#define CAS_DEFAULT_DEBUG FALSE
#define CAS_DEFAULT_SCOPE NULL
#define CAS_DEFAULT_RENEW NULL
#define CAS_DEFAULT_GATEWAY NULL
#define CAS_DEFAULT_VALIDATE_SERVER 1
#define CAS_DEFAULT_VALIDATE_DEPTH 9
#define CAS_DEFAULT_ALLOW_WILDCARD_CERT 0
#define CAS_DEFAULT_CA_PATH "/etc/ssl/certs/"
#define CAS_DEFAULT_COOKIE_PATH "/dev/null"
#define CAS_DEFAULT_LOGIN_URL "https://login.example.com/cas/login"
#define CAS_DEFAULT_VALIDATE_V1_URL "https://login.example.com/cas/validate"
#define CAS_DEFAULT_VALIDATE_V2_URL "https://login.example.com/cas/serviceValidate"
#define CAS_DEFAULT_VALIDATE_URL CAS_DEFAULT_VALIDATE_V2_URL
#define CAS_DEFAULT_PROXY_VALIDATE_URL "https://login.example.com/cas/proxyValidate"
#define CAS_DEFAULT_COOKIE_ENTROPY 32
#define CAS_DEFAULT_COOKIE_TIMEOUT 7200 /* 2 hours */
#define CAS_DEFAULT_COOKIE_IDLE_TIMEOUT 3600 /* 1 hour */
#define CAS_DEFAULT_CACHE_CLEAN_INTERVAL  1800 /* 30 minutes */
#define CAS_DEFAULT_COOKIE "MOD_AUTH_CAS"
#define CAS_DEFAULT_SCOOKIE "MOD_AUTH_CAS_S"
#define CAS_DEFAULT_GATEWAY_COOKIE "MOD_CAS_G"
#define CAS_DEFAULT_AUTHN_HEADER NULL

#ifdef WIN32
typedef SOCKET socket_t;
#else
typedef int socket_t;
#define INVALID_SOCKET -1
#endif

typedef struct cas_cfg {
	unsigned int CASVersion;
	unsigned int CASDebug;
	unsigned int CASValidateServer;
	unsigned int CASValidateDepth;
	unsigned int CASAllowWildcardCert;
	unsigned int CASCacheCleanInterval;
	unsigned int CASCookieEntropy;
	unsigned int CASTimeout;
	unsigned int CASIdleTimeout;
	char *CASCertificatePath;
	char *CASCookiePath;
	apr_uri_t CASLoginURL;
	apr_uri_t CASValidateURL;
	apr_uri_t CASProxyValidateURL;
} cas_cfg;

typedef struct cas_dir_cfg {
	char *CASScope;
	char *CASRenew;
	char *CASGateway;
	char *CASCookie;
	char *CASSecureCookie;
	char *CASGatewayCookie;
	char *CASAuthNHeader;
} cas_dir_cfg;

typedef struct cas_cache_entry {
	char *user;
	apr_time_t issued;
	apr_time_t lastactive;
	char *path;
	apr_byte_t renewed;
	apr_byte_t secure;
} cas_cache_entry;

typedef enum { cmd_version, cmd_debug, cmd_validate_server, cmd_validate_depth, cmd_wildcard_cert, cmd_ca_path, cmd_cookie_path, cmd_loginurl, cmd_validateurl, cmd_proxyurl, cmd_cookie_entropy, cmd_session_timeout, cmd_idle_timeout, cmd_cache_interval } valid_cmds;

module AP_MODULE_DECLARE_DATA auth_cas_module;
static apr_byte_t cas_setURL(apr_pool_t *pool, apr_uri_t *uri, const char *url);
static void *cas_create_server_config(apr_pool_t *pool, server_rec *svr);
static void *cas_create_dir_config(apr_pool_t *pool, char *path);
static void *cas_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
static const char *cfg_readCASParameter(cmd_parms *cmd, void *cfg, const char *value);
static apr_byte_t check_cert_cn(request_rec *r, cas_cfg *c, SSL_CTX *ctx, X509 *certificate, char *cn);
static char *getResponseFromServer (request_rec *r, cas_cfg *c, char *ticket);
static apr_byte_t isValidCASTicket(request_rec *r, cas_cfg *c, char *ticket, char **user);
static apr_byte_t isSSL(request_rec *r);
static apr_byte_t readCASCacheFile(request_rec *r, cas_cfg *c, char *name, cas_cache_entry *cache);
static void CASCleanCache(request_rec *r, cas_cfg *c);
static apr_byte_t isValidCASCookie(request_rec *r, cas_cfg *c, char *cookie, char **user);
static char *getCASCookie(request_rec *r, char *cookieName);
static char *createCASCookie(request_rec *r, char *user);
static void setCASCookie(request_rec *r, char *cookieName, char *cookieValue, apr_byte_t secure);
static char *escapeString(request_rec *r, char *str);
static char *getCASGateway(request_rec *r);
static char *getCASRenew(request_rec *r);
static char *getCASValidateURL(request_rec *r, cas_cfg *c);
static char *getCASLoginURL(request_rec *r, cas_cfg *c);
static char *getCASService(request_rec *r, cas_cfg *c);
static void redirectRequest(request_rec *r, cas_cfg *c);
static char *getCASTicket(request_rec *r);
static void removeCASParams(request_rec *r);
static int cas_authenticate(request_rec *r);
static void cas_register_hooks(apr_pool_t *p);

/* Uncomment to compile for Apache 2.0, or use -DAPACHE2_0 from gcc command line */
// #define APACHE2_0

/* apr forward compatibility */
#ifndef APR_FOPEN_READ
#define APR_FOPEN_READ		APR_READ
#endif

#ifndef APR_FOPEN_WRITE
#define APR_FOPEN_WRITE		APR_WRITE
#endif

#ifndef APR_FOPEN_CREATE
#define APR_FOPEN_CREATE	APR_CREATE
#endif

#ifndef APR_FPROT_UWRITE
#define APR_FPROT_UWRITE	APR_UWRITE
#endif

#ifndef APR_FPROT_UREAD
#define APR_FPROT_UREAD		APR_UREAD
#endif
