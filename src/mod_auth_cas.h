/*
 *
 * Copyright 2011 the mod_auth_cas team.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * mod_auth_cas.h
 * Apache CAS Authentication Module
 * Version 1.0.10
 *
 * Contact: cas-user@apereo.org
 *
 */

#ifndef MOD_AUTH_CAS_H
#define MOD_AUTH_CAS_H

#include <stddef.h>
#include <http_core.h>
#include "ap_release.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>

#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x01000000)
#define OPENSSL_NO_THREADID
#endif

#include "curl/curl.h"
#include "curl/curlver.h"
#if (LIBCURL_VERSION_NUM < 0x071304)
#define LIBCURL_NO_CURLPROTO
#endif

#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211
#include "mod_auth.h"
#endif

#include "cas_saml_attr.h"

#ifndef AP_SERVER_MAJORVERSION_NUMBER
	#ifndef AP_SERVER_MINORVERSION_NUMBER
		#define APACHE2_0
	#endif
#endif

#ifndef APACHE2_0
	#ifdef AP_SERVER_MAJORVERSION_NUMBER
		#ifdef AP_SERVER_MINORVERSION_NUMBER
			#if ((AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER == 0))
				#define APACHE2_0
			#endif
		#endif
	#endif
#endif

#define CAS_DEFAULT_VERSION 2
#define CAS_DEFAULT_DEBUG FALSE
#define CAS_DEFAULT_SCOPE NULL
#define CAS_DEFAULT_RENEW NULL
#define CAS_DEFAULT_GATEWAY NULL
#define CAS_DEFAULT_VALIDATE_SAML 0
#define CAS_DEFAULT_ATTRIBUTE_DELIMITER ","
#if MODULE_MAGIC_NUMBER_MAJOR < 20120211
	#define CAS_DEFAULT_ATTRIBUTE_PREFIX "CAS_"
#else
	#define CAS_DEFAULT_ATTRIBUTE_PREFIX "CAS-"
#endif
#define CAS_DEFAULT_VALIDATE_DEPTH 9
#define CAS_DEFAULT_CA_PATH "/etc/ssl/certs/"
#define CAS_DEFAULT_COOKIE_PATH "/dev/null"
#define CAS_DEFAULT_LOGIN_URL NULL
#define CAS_DEFAULT_VALIDATE_V1_URL NULL
#define CAS_DEFAULT_VALIDATE_V2_URL NULL
#define CAS_DEFAULT_VALIDATE_URL CAS_DEFAULT_VALIDATE_V2_URL
#define CAS_DEFAULT_PROXY_VALIDATE_URL NULL
#define CAS_DEFAULT_ROOT_PROXIED_AS_URL NULL
#define CAS_DEFAULT_COOKIE_ENTROPY 32
#define CAS_DEFAULT_COOKIE_DOMAIN NULL
#define CAS_DEFAULT_COOKIE_HTTPONLY 1
#define CAS_DEFAULT_COOKIE_TIMEOUT 7200 /* 2 hours */
#define CAS_DEFAULT_COOKIE_IDLE_TIMEOUT 3600 /* 1 hour */
#define CAS_DEFAULT_CACHE_CLEAN_INTERVAL  1800 /* 30 minutes */
#define CAS_DEFAULT_COOKIE "MOD_AUTH_CAS"
#define CAS_DEFAULT_SCOOKIE "MOD_AUTH_CAS_S"
#define CAS_DEFAULT_GATEWAY_COOKIE "MOD_CAS_G"
#define CAS_DEFAULT_GATEWAY_COOKIE_DOMAIN NULL
#define CAS_DEFAULT_AUTHN_HEADER NULL
#define CAS_DEFAULT_SCRUB_REQUEST_HEADERS NULL
#define CAS_DEFAULT_SSO_ENABLED FALSE
#define CAS_DEFAULT_AUTHORITATIVE FALSE
#define CAS_DEFAULT_PRESERVE_TICKET FALSE

#define CAS_MAX_RESPONSE_SIZE 2147483648
#define CAS_MAX_ERROR_SIZE 1024
#define CAS_MAX_XML_SIZE 1024

#define CAS_ATTR_MATCH 0
#define CAS_ATTR_NO_MATCH 1

#define CAS_SESSION_EXPIRE_SESSION_SCOPE_TIMEOUT -1
#define CAS_SESSION_EXPIRE_COOKIE_NOW 0

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef struct cas_cfg {
	/* non-zero if this is a merged vhost config */
	unsigned int merged;
	unsigned int CASVersion;
	unsigned int CASDebug;
	unsigned int CASValidateDepth;
	unsigned int CASCacheCleanInterval;
	unsigned int CASCookieEntropy;
	unsigned int CASTimeout;
	unsigned int CASIdleTimeout;
	unsigned int CASCookieHttpOnly;
	unsigned int CASSSOEnabled;
	unsigned int CASAuthoritative;
	unsigned int CASPreserveTicket;
	unsigned int CASValidateSAML;
	char *CASCertificatePath;
	char *CASCookiePath;
	char *CASCookieDomain;
	char *CASGatewayCookieDomain;
	char *CASAttributeDelimiter;
	char *CASAttributePrefix;
	apr_uri_t CASLoginURL;
	apr_uri_t CASValidateURL;
	apr_uri_t CASProxyValidateURL;
	apr_uri_t CASRootProxiedAs;
} cas_cfg;

typedef struct cas_dir_cfg {
	char *CASScope;
	char *CASRenew;
	char *CASGateway;
	char *CASCookie;
	char *CASSecureCookie;
	char *CASGatewayCookie;
	char *CASAuthNHeader;
	char *CASScrubRequestHeaders;
} cas_dir_cfg;

typedef struct cas_cache_entry {
	char *user;
	apr_time_t issued;
	apr_time_t lastactive;
	char *path;
	apr_byte_t renewed;
	apr_byte_t secure;
	char *ticket;
	cas_saml_attr *attrs;
} cas_cache_entry;

typedef struct cas_curl_buffer {
	char *buf;
	size_t written;
	apr_pool_t *pool;
	apr_pool_t *subpool;
} cas_curl_buffer;

typedef enum {
	cmd_version, cmd_debug, cmd_validate_depth, cmd_ca_path, cmd_cookie_path,
	cmd_loginurl, cmd_validateurl, cmd_proxyurl, cmd_cookie_entropy, cmd_session_timeout,
	cmd_idle_timeout, cmd_cache_interval, cmd_cookie_domain, cmd_cookie_httponly,
	cmd_sso, cmd_validate_saml, cmd_attribute_delimiter, cmd_attribute_prefix,
	cmd_root_proxied_as, cmd_authoritative, cmd_preserve_ticket, cmd_gateway_cookie_domain
} valid_cmds;

module AP_MODULE_DECLARE_DATA auth_cas_module;
apr_byte_t cas_setURL(apr_pool_t *pool, apr_uri_t *uri, const char *url);
void *cas_create_server_config(apr_pool_t *pool, server_rec *svr);
void *cas_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD);
void *cas_create_dir_config(apr_pool_t *pool, char *path);
void *cas_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
const char *cfg_readCASParameter(cmd_parms *cmd, void *cfg, const char *value);
char *getResponseFromServer (request_rec *r, cas_cfg *c, char *ticket);
apr_byte_t validCASTicketFormat(const char *ticket);
apr_byte_t isValidCASTicket(request_rec *r, cas_cfg *c, char *ticket, char **user, cas_saml_attr **attrs);
int cas_char_to_env(int c);
int cas_strnenvcmp(const char *a, const char *b, int len);
apr_table_t *cas_scrub_headers(apr_pool_t *p, const char *const attr_prefix,
	const char *const authn_header, const apr_table_t *const headers,
	const apr_table_t **const dirty_headers_ptr);
char *normalizeHeaderName(const request_rec *r, const char *str);
apr_byte_t isSSL(const request_rec *r);
apr_byte_t readCASCacheFile(request_rec *r, cas_cfg *c, char *name, cas_cache_entry *cache);
void CASCleanCache(request_rec *r, cas_cfg *c);
apr_byte_t writeCASCacheEntry(request_rec *r, char *name, cas_cache_entry *cache, apr_byte_t exists);
char *createCASCookie(request_rec *r, char *user, cas_saml_attr *attrs, char *ticket);
apr_byte_t isValidCASCookie(request_rec *r, cas_cfg *c, char *cookie, char **user, cas_saml_attr **attrs);
size_t cas_curl_write(const void *ptr, size_t size, size_t nmemb, void *stream);
char *getCASCookie(request_rec *r, char *cookieName);
char *getCASPath(request_rec *r);
void CASSAMLLogout(request_rec *r, char *body);
apr_status_t cas_in_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
void deleteCASCacheFile(request_rec *r, char *cookieName);
void setCASCookie(request_rec *r, char *cookieName, char *cookieValue, apr_byte_t secure, apr_time_t expireTime, char *cookieDomain);
char *escapeString(const request_rec *r, const char *str);
char *urlEncode(const request_rec *r, const char *str, const char *charsToEncode);
char *getCASGateway(request_rec *r);
char *getCASRenew(request_rec *r);
char *getCASLoginURL(request_rec *r, cas_cfg *c);
char *getCASService(const request_rec *r, const cas_cfg *c);
void redirectRequest(request_rec *r, cas_cfg *c);
char *getCASTicket(request_rec *r);
apr_byte_t removeCASParams(request_rec *r);
int cas_authenticate(request_rec *r);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef OPENSSL_NO_THREADID
unsigned long cas_ssl_id_callback(void);
#else
void cas_ssl_id_callback(CRYPTO_THREADID *id);
#endif
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
int cas_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s);
void cas_register_hooks(apr_pool_t *p);

char *getCASScope(request_rec *r);
void expireCASST(request_rec *r, const char *ticketname);
void cas_scrub_request_headers(request_rec *r, const cas_cfg *const c, const cas_dir_cfg *const d);
CURLcode cas_curl_ssl_ctx(CURL *curl, void *sslctx, void *parm);
apr_status_t cas_cleanup(void *data);
int check_merged_vhost_configs(apr_pool_t *pool, server_rec *s);
int check_vhost_config(apr_pool_t *pool, server_rec *s);
int merged_vhost_configs_exist(server_rec *s);

#if (defined(OPENSSL_THREADS) && APR_HAS_THREADS)
void cas_ssl_locking_callback(int mode, int type, const char *file, int line);
#endif
/* Access per-request CAS SAML attributes */
void cas_set_attributes(request_rec *r, cas_saml_attr *const attrs);
const cas_saml_attr *cas_get_attributes(request_rec *r);
int cas_match_attribute(const char *const attr_spec, const cas_saml_attr *const attributes, struct request_rec *r);

/* Authorization check */
#if MODULE_MAGIC_NUMBER_MAJOR < 20120211
int cas_authorize(request_rec *r);
int cas_authorize_worker(request_rec *r, const cas_saml_attr *const attrs, const require_line *const reqs, int nelts, const cas_cfg *const c);
#else
authz_status cas_check_authorization(request_rec *r, const char *require_line, const void *parsed_require_line);
#endif

/* Fancy wrapper around flock() */
int cas_flock(apr_file_t *fileHandle, int lockOperation, request_rec *r);

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



#endif /* MOD_AUTH_CAS_H */
