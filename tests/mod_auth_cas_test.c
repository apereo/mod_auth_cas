#include <check.h>
#include <stdio.h>

#include <apr.h>
#include <apr_file_io.h>
#include <apr_general.h>
#include <apr_portable.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_config.h>
#include <util_filter.h>
#include <util_md5.h>
#include <mod_include.h>

#include "../src/mod_auth_cas.h"
#include "cas_saml_attr_test.h"
#include "curl_stubs.h"

int find_entries_in_list(void *, const char *, const char *);
char *get_attr(cas_cfg *, cas_saml_attr *, const char *);
char *rand_str(apr_pool_t *, unsigned int);
void core_setup(void);
void core_teardown(void);
Suite *mod_auth_cas_suite(void);

request_rec *request;
apr_pool_t *pool;

/* Function prototypes to make gcc happy */
int find_entries_in_list(void *rec, const char *key, const char *val);
char *get_attr(cas_cfg *c, cas_saml_attr *attrs, const char *attr);
char *rand_str(apr_pool_t *p, unsigned int length_limit);
void core_setup(void);
void core_teardown(void);
Suite *mod_auth_cas_suite(void);


/* The tests */
START_TEST(cas_merge_server_config_test) {
  cas_cfg *base = cas_create_server_config(request->pool, NULL);
  cas_cfg *add = cas_create_server_config(request->pool, NULL);
  cas_cfg *merged;
  apr_uri_t uri;

  fail_if(base->merged == TRUE);
  fail_if(add->merged == TRUE);

  memset(&uri, 0, sizeof(uri));
  uri.scheme = "http";
  uri.hostname = "example.com";

  /* just tweak some random values of different basic types */
  add->CASDebug = TRUE;
  add->CASVersion = 1;
  add->CASCertificatePath = "/dev/null";
  add->CASLoginURL = uri;

  merged = (cas_cfg *) cas_merge_server_config(request->pool, (void *)base,
                                               (void *)add);
  fail_if(base->merged == TRUE);
  fail_if(add->merged == TRUE);

  /* Check the values from above. */
  fail_unless(merged->CASDebug == TRUE);
  fail_unless(merged->merged == TRUE);
  fail_unless(merged->CASVersion == 1);
  fail_unless(strcmp(merged->CASCertificatePath, "/dev/null") == 0);
  fail_unless(strcmp(merged->CASLoginURL.scheme, "http") == 0);
  fail_unless(strcmp(merged->CASLoginURL.hostname, "example.com") == 0);
}
END_TEST

START_TEST(cas_merge_dir_config_test) {
  cas_dir_cfg *merged;
  cas_dir_cfg *base = cas_create_dir_config(request->pool, NULL);
  cas_dir_cfg *add = cas_create_dir_config(request->pool, NULL);

  add->CASCookie = "XYZ";
  merged = (cas_dir_cfg *) cas_merge_dir_config(request->pool,
                                                             (void *)base,
                                                             (void *)add);
  fail_unless(strcmp(merged->CASCookie, "XYZ") == 0);
}
END_TEST

START_TEST(cas_setURL_test) {
  const char *url1 = "http://www.example.com/";
  const char *url2 = "http://www.example.com:8080/foo.html";
  const char *url3 = "http://[foo";
  const char *url4 = "kwyjibo";
  apr_uri_t uri;

  cas_setURL(request->pool, &uri, url1);
  fail_unless(uri.port == 80);

  cas_setURL(request->pool, &uri, url2);
  fail_unless(uri.port == 8080);

  fail_unless(cas_setURL(request->pool, &uri, url3) == FALSE);
  fail_unless(cas_setURL(request->pool, &uri, url4) == FALSE);
  fail_unless(cas_setURL(request->pool, &uri, NULL) == FALSE);
}
END_TEST

START_TEST(isSSL_test) {
  /* stuff state into an arbitrary place in the pool */
  apr_pool_userdata_set("https", "scheme", NULL, request->pool);
  fail_unless(isSSL(request) == TRUE);
  apr_pool_userdata_set("http", "scheme", NULL, request->pool);
  fail_unless(isSSL(request) == FALSE);
}
END_TEST

START_TEST(cas_char_to_env_test) {
  int i;
  for (i = 0; i < 255; i++) {
    if (i >= 'a' && i <= 'z')
      fail_unless(cas_char_to_env(i) == (i & 0xDF));
    else if((i >= '0' && i <= '9') || (i >= 'A' && i <= 'Z'))
      fail_unless(cas_char_to_env(i) == i);
    else
      fail_unless(cas_char_to_env(i) == (int) '_');
  }
}
END_TEST

const char *invalid_headers[] = {
  "CaS-Foo",
  "cAs-Bar",
  "CaS_Baz",
  "cas:zot",
  "CAS-Zuz",
  /*
   * CAS_DEFAULT_AUTHN_HEADER is NULL, but we want to make sure that such a
   * header is removed (and we want it to start with something other than the
   * CAS attribute prefix).
   */
  "MAC-User"
};

const char *valid_headers[] = {
  "User-Agent",
  "Host",
};

struct header_info {
  int num_headers;
  const char **headers;
};

int find_entries_in_list(void *rec, const char *key, const char *val)
{
  int rv = 0, i;
  struct header_info *hi = (struct header_info *) rec;

  for (i = 0; i < hi->num_headers; i++) {
    if (strcmp(hi->headers[i], key) == 0) {
      rv++;
      break;
    }
  }
  return rv;
}

START_TEST(cas_scrub_headers_test) {
  struct header_info hi;
  apr_table_t *headers_in, *headers_out;
  const apr_table_t *dirty_headers;
  size_t sz;

  headers_in = apr_table_make(pool, ARRAY_SIZE(valid_headers) +
                                    ARRAY_SIZE(invalid_headers));

  for (sz = 0; sz < ARRAY_SIZE(valid_headers); sz++)
    apr_table_add(headers_in, valid_headers[sz], "Value");

  for (sz = 0; sz < ARRAY_SIZE(invalid_headers); sz++)
    apr_table_add(headers_in, invalid_headers[sz], "Value");

  headers_out = cas_scrub_headers(pool,
                                  CAS_DEFAULT_ATTRIBUTE_PREFIX,
                                  "MAC-User",
                                  headers_in,
                                  &dirty_headers);

  hi.num_headers = ARRAY_SIZE(valid_headers);
  hi.headers = valid_headers;
  fail_if(apr_table_do(find_entries_in_list, &hi, headers_out, NULL) == 0);

  hi.num_headers = ARRAY_SIZE(invalid_headers);
  hi.headers = invalid_headers;
  fail_if(apr_table_do(find_entries_in_list, &hi, dirty_headers, NULL) == 0);
}

END_TEST

START_TEST(normalizeHeaderName_test) {
  fail_unless(strcmp(normalizeHeaderName(request, "foobar"), "foobar") == 0);
  fail_unless(strcmp(normalizeHeaderName(request, "FooBar"), "FooBar") == 0);
  fail_unless(strcmp(normalizeHeaderName(request, "Foo Bar"), "Foo-Bar") == 0);
  fail_unless(strcmp(normalizeHeaderName(request, "Foo:Bar"), "Foo-Bar") == 0);
}
END_TEST

START_TEST(getCASPath_test) {
  char *path;

  request->parsed_uri.path = "";
  path = getCASPath(request);
  fail_unless(strcmp(path, "/") == 0);

  request->parsed_uri.path = "/";
  path = getCASPath(request);
  fail_unless(strcmp(path, "/") == 0);

  request->parsed_uri.path = "/foo.html";
  path = getCASPath(request);
  fail_unless(strcmp(path, "/") == 0);

  request->parsed_uri.path = "/foo/bar/baz.html";
  path = getCASPath(request);
  fail_unless(strcmp(path, "/foo/bar/") == 0);

  request->parsed_uri.path = "/foo/bar/baz.html/";
  path = getCASPath(request);
  fail_unless(strcmp(path, "/foo/bar/baz.html/") == 0);
}
END_TEST

START_TEST(getCASScope_test) {
  apr_uri_parse(request->pool, "http://www.example.com/foo/bar/baz.html",
                &request->parsed_uri);
  /* different control paths need to be tested -- c->CASDebug, c->CASGateway
   * for correct and incorrect path, CASRenew, ... */
  fail();
}
END_TEST

START_TEST(getCASGatewayV1_test) {
  char *rv;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  cas_dir_cfg *d = ap_get_module_config(request->per_dir_config,
                                        &auth_cas_module);
  c->CASVersion = 1;
  d->CASGateway = "/foo";
  request->parsed_uri.path = "/foo/bar";
  rv = getCASGateway(request);
  fail_unless(strcmp(getCASGateway(request), "") == 0);
}
END_TEST

START_TEST(getCASGatewayV2_test) {
  char *rv;
  cas_dir_cfg *d = ap_get_module_config(request->per_dir_config,
                                        &auth_cas_module);
  d->CASGateway = "/foo";
  request->parsed_uri.path = "/foo/bar";
  rv = getCASGateway(request);
  fail_unless(strcmp(getCASGateway(request), "&gateway=true") == 0);

  request->parsed_uri.path = "/baz";
  fail_unless(strcmp(getCASGateway(request), "") == 0);
}
END_TEST

START_TEST(getCASRenew_test) {
  char *rv;
  cas_dir_cfg *d = ap_get_module_config(request->per_dir_config,
                                        &auth_cas_module);
  d->CASRenew = "/foo";
  request->parsed_uri.path = "/foo/bar";
  rv = getCASRenew(request);
  fail_unless(strcmp(getCASRenew(request), "&renew=true") == 0);

  request->parsed_uri.path = "/baz";
  fail_unless(strcmp(getCASRenew(request), "") == 0);
}
END_TEST

START_TEST(getCASLoginURL_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  const char *url = "https://user:password@login.example.com/cas/login?foo=bar";
  char *rv;
  apr_uri_t parsed_url;
  apr_uri_parse(request->pool, url, &parsed_url);
  memcpy(&c->CASLoginURL, &parsed_url, sizeof(apr_uri_t));
  rv = getCASLoginURL(request, c);
  fail_unless(strcmp(rv, "https://login.example.com/cas/login") == 0);
}
END_TEST

START_TEST(getCASService_http_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  char *service;
  const char *expected_service =
      "http%3a%2f%2ffoo.example.com%2ffoo%3fbar%3dbaz%26zot%3dqux";

  apr_pool_userdata_set("http", "scheme", NULL, request->pool);

  service = getCASService(request, c);
  fail_unless(strcmp(service, expected_service) == 0);
}
END_TEST

START_TEST(getCASService_https_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  char *service;
  const char *expected_service =
      "https%3a%2f%2ffoo.example.com%2ffoo%3fbar%3dbaz%26zot%3dqux";

  apr_pool_userdata_set("https", "scheme", NULL, request->pool);
  request->connection->local_addr->port = 443;

  service = getCASService(request, c);
  fail_unless(strcmp(service, expected_service) == 0);
}
END_TEST

START_TEST(getCASService_http_port_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  char *service;
  const char *expected_service =
      "http%3a%2f%2ffoo.example.com%3a8080%2ffoo%3fbar%3dbaz%26zot%3dqux";

  apr_pool_userdata_set("http", "scheme", NULL, request->pool);
  request->connection->local_addr->port = 8080;

  service = getCASService(request, c);
  fail_unless(strcmp(service, expected_service) == 0);
}
END_TEST

START_TEST(getCASService_https_port_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  char *service;
  const char *expected_service =
      "https%3a%2f%2ffoo.example.com%3a8443%2ffoo%3fbar%3dbaz%26zot%3dqux";

  apr_pool_userdata_set("https", "scheme", NULL, request->pool);
  request->connection->local_addr->port = 8443;

  service = getCASService(request, c);
  fail_unless(strcmp(service, expected_service) == 0);
}
END_TEST

START_TEST(getCASService_root_proxied_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  char *service;
  const char *expected_service =
      "http%3a%2f%2frev-proxy.example.com%2fapp%2ffoo%3fbar%3dbaz%26zot%3dqux";
  const char *root = "http://rev-proxy.example.com/app";
  apr_uri_t parsed_url;
  apr_uri_parse(request->pool, root, &parsed_url);
  apr_pool_userdata_set("https", "scheme", NULL, request->pool);
  request->connection->local_addr->port = 9999;
  memcpy(&c->CASRootProxiedAs, &parsed_url, sizeof(apr_uri_t));

  service = getCASService(request, c);
  fail_unless(strcmp(service, expected_service) == 0);
}
END_TEST

START_TEST(getCASService_empty_qs_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  char *service;
  const char *expected_service =
      "http%3a%2f%2ffoo.example.com%2f";

  apr_pool_userdata_set("http", "scheme", NULL, request->pool);
  request->uri = "/";
  request->args = "";
  request->unparsed_uri = "/?";

  service = getCASService(request, c);
  fail_unless(strcmp(service, expected_service) == 0);

  request->args = NULL;
  request->unparsed_uri = "/";
  service = getCASService(request, c);
  fail_unless(strcmp(service, expected_service) == 0);
}
END_TEST

START_TEST(redirectRequest_test) {
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  const char *expected = "https://login.example.com/cas/login?service=http%3a"
      "%2f%2ffoo.example.com%2ffoo%3fbar%3dbaz%26zot%3dqux", *rv;
  fail_unless(apr_table_get(request->headers_out, "Location") == NULL);
  apr_pool_userdata_set("http", "scheme", NULL, request->pool);
  redirectRequest(request, c);

  rv = apr_table_get(request->headers_out, "Location");
  fail_if(rv == NULL);
  fail_unless(strcmp(rv, expected) == 0);
}
END_TEST

START_TEST(removeCASParams_test) {
  char *only_ticket = "ticket=ST-1234";
  char *args_and_ticket = "foo=bar&ticket=ST-1234";
  const char *args_and_ticket_expected = "foo=bar";
  char *ticket_in_middle = "foo=bar&ticket=ST-1234&baz=zot";
  const char *ticket_in_middle_expected = "foo=bar&baz=zot";
  char *non_cas = "foo=bar&ticket=not-a-cas-ticket";
  const char *non_cas_expected = "foo=bar&ticket=not-a-cas-ticket";
  char *cas_and_non_ticket =
      "foo=bar&ticket=not-a-cas-ticket&ticket=ST-1234";
  const char *cas_and_non_ticket_expected =
      "foo=bar&ticket=not-a-cas-ticket";
  /* XXX: is this really what we want? */
  char *dup_ticket = "foo=bar&ticket=ST-1234&ticket=ST-1234";
  const char *dup_ticket_expected = "foo=bar";


  request->args = apr_pstrdup(request->pool, only_ticket);
  fail_if(removeCASParams(request) == FALSE);
  fail_unless(request->args == NULL);

  request->args = apr_pstrdup(request->pool, args_and_ticket);
  fail_if(removeCASParams(request) == FALSE);
  fail_unless(strcmp(request->args, args_and_ticket_expected) == 0);

  request->args = apr_pstrdup(request->pool, ticket_in_middle);
  fail_if(removeCASParams(request) == FALSE);
  fail_unless(strcmp(request->args, ticket_in_middle_expected) == 0);

  request->args = apr_pstrdup(request->pool, non_cas);
  fail_if(removeCASParams(request) == TRUE);
  fail_unless(strcmp(request->args, non_cas_expected) == 0);

  request->args = apr_pstrdup(request->pool, cas_and_non_ticket);
  fail_if(removeCASParams(request) == FALSE);
  fail_unless(strcmp(request->args, cas_and_non_ticket_expected) == 0);

  request->args = apr_pstrdup(request->pool, dup_ticket);
  fail_if(removeCASParams(request) == FALSE);
  fail_unless(strcmp(request->args, dup_ticket_expected) == 0);

}
END_TEST

START_TEST(validCASTicketFormat_test) {
  const char *valid[] = {
    "ST-1234",
    "ST-1234-login.example.com"
  };
  const char *invalid[] = {
    "ST-<^>",
    "ST-\x22qwe", /* ST-"qwe */
    "ST-\x25qwe", /* ST-<nak>qwe */
    "ST-\xc8qwe"  /* ST-<ascii 200>qwe */
  };
  unsigned int i;

  for (i = 0; i < ARRAY_SIZE(valid); i++)
    fail_unless(validCASTicketFormat(valid[i]) == TRUE);

  for (i = 0; i < ARRAY_SIZE(invalid); i++)
    fail_unless(validCASTicketFormat(invalid[i]) == FALSE);
}
END_TEST

START_TEST(getCASTicket_test) {
  char *args = "foo=bar&ticket=ST-1234&baz=zot";
  char *dupargs = "foo=bar&ticket=ST-^<>&baz=zot&ticket=ST-1234";
  char *badargs = "foo=bar&ticket=ST-^<>&baz=zot";
  char *emptyargs = "";
  char *truncated_args = "ST-";
  char *rv;
  const char *expected = "ST-1234";


  request->args = apr_pstrdup(request->pool, args);
  rv = getCASTicket(request);
  fail_unless(strcmp(rv, expected) == 0);

  request->args = apr_pstrdup(request->pool, dupargs);
  rv = getCASTicket(request);
  fail_unless(strcmp(rv, expected) == 0);

  request->args = apr_pstrdup(request->pool, badargs);
  rv = getCASTicket(request);
  fail_unless(rv == NULL);

  request->args = apr_pstrdup(request->pool, emptyargs);
  rv = getCASTicket(request);
  fail_unless(rv == NULL);

  request->args = apr_pstrdup(request->pool, truncated_args);
  rv = getCASTicket(request);
  fail_unless(rv == NULL);

  request->args = NULL;
  rv = getCASTicket(request);
  fail_unless(rv == NULL);
}
END_TEST

START_TEST(getCASCookie_test) {
  const char *expected = "0123456789abcdef";
  cas_dir_cfg *d = ap_get_module_config(request->per_dir_config,
                                        &auth_cas_module);
  fail_unless(strcmp(getCASCookie(request, d->CASCookie), expected) == 0);
}
END_TEST

START_TEST(setCASCookie_test) {
  const char *expected = "cookie_name=cookie_value;Path=/";
  const char *rv;
  fail_if (apr_table_get(request->err_headers_out, "Set-Cookie") != NULL);
  setCASCookie(request, "cookie_name", "cookie_value", FALSE, CAS_SESSION_EXPIRE_SESSION_SCOPE_TIMEOUT);
  rv = apr_table_get(request->err_headers_out, "Set-Cookie");
  fail_unless(strcmp(rv, expected) == 0);

  /* TODO(pames): test with CASRootProxiedAs */
  /* TODO(pames): test with secure, domain, httponly, a specific path... */
}
END_TEST

START_TEST(setCASCookieExpiryNow_test) {
	const char *expected = "cookie_name=cookie_value;Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
	const char *ernVal;

  fail_if (apr_table_get(request->err_headers_out, "Set-Cookie") != NULL);
	setCASCookie(request, "cookie_name", "cookie_value", FALSE, CAS_SESSION_EXPIRE_COOKIE_NOW);
	ernVal = apr_table_get(request->err_headers_out, "Set-Cookie");
	fail_unless(0 == strcmp(ernVal, expected), ernVal);
}
END_TEST

START_TEST(setCASCookieExpiryFiveSeconds_test) {
  const char *expected = "cookie_name=cookie_value;Path=/; expires=Thu, 01 Jan 1970 00:00:05 GMT";
  const char *eeVal;
  apr_time_t fiveSecPastEpoch = 5000000;

  fail_if (apr_table_get(request->err_headers_out, "Set-Cookie") != NULL);
  setCASCookie(request, "cookie_name", "cookie_value", FALSE, fiveSecPastEpoch);
  eeVal = apr_table_get(request->err_headers_out, "Set-Cookie");
  fail_unless(0 == strcmp(eeVal, expected), eeVal);
}
END_TEST

START_TEST(getCASCookie_empty_test) {
  const char *expected = "";
  cas_dir_cfg *d = ap_get_module_config(request->per_dir_config,
                                        &auth_cas_module);
  /*
   * setup request with empty cookie header
   */
  apr_table_set(request->headers_in, "Cookie", "");
  fail_unless(getCASCookie(request, d->CASCookie) == NULL);
}
END_TEST

START_TEST(removeGatewayCookie_test) {
  const char *expected = "MOD_CAS_G=TRUE;Secure;Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  const char *ernVal;
  const char *response =
	"<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">"
	"<cas:authenticationSuccess>"
	"<cas:user>good</cas:user>"
	"</cas:authenticationSuccess>"
	"</cas:serviceResponse>";
  int rv;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  c->CASCookiePath = "/tmp/";

  /*
   * setup request as if we've just returned from a gateway trip,
   * with a gateway cookie and a cas ticket
   */
  apr_table_set(request->headers_in, "Cookie", "MOD_CAS_G=TRUE; cookie_name=cookie_value ");
  request->unparsed_uri = "/foo?ticket=ST-1234";
  request->uri = "/foo";
  request->args = apr_pstrdup(request->pool, "ticket=ST-1234");
  request->connection->local_addr->port = 443;
  request->ap_auth_type = "cas";
  fail_unless(strcmp(request->args, "ticket=ST-1234") == 0, request->args);
  apr_uri_parse(request->pool, "http://foo.example.com/foo?ticket=ST-12345",
                &request->parsed_uri);

  /*
   * setup fake serviceValidate response from cas server
   */
  set_curl_response(response);

  /*
   * authenticate the user
   */
  c->CASCertificatePath = "/";
  rv = cas_authenticate(request);
  fail_unless(rv == HTTP_MOVED_TEMPORARILY, "cas_authenticate failed");
  fail_unless(strcmp(request->user, "good") == 0, request->user);

  /*
   * verify that the Set-Cookie header removes the gateway cookie
   */
  apr_table_compress(request->err_headers_out, APR_OVERLAP_TABLES_MERGE);
  ernVal = apr_table_get(request->err_headers_out, "Set-Cookie");
  fail_unless(strstr(ernVal, expected) != NULL, ernVal);
}
END_TEST

START_TEST(escapeString_test) {
  char *rv, *expected;
  rv = escapeString(request, "a+b c<d>e\"f%g{h}i|j\\k^l~m[n]o`p;q/r?s:t@u=v&"
                             "w#x");
  /*
   * output of python's urllib.quote(...).lower(), and replacing the remaining
   * '/' with %2f (it doesn't encode that for some reason.
   */
  expected = "a%2bb%20c%3cd%3ee%22f%25g%7bh%7di%7cj%5ck%5el%7em%5bn%5do%60p"
             "%3bq%2fr%3fs%3at%40u%3dv%26w%23x";
  fail_unless(strcmp(rv, expected) == 0);
}
END_TEST

START_TEST(urlEncode_test) {
  char *s;
  s = urlEncode(request, "A b", " A");
  fail_unless(strcmp(s, "%41%20b") == 0);

}
END_TEST

START_TEST(readCASCacheFile_test) {
  apr_file_t *f;
  apr_size_t sz;
  cas_cache_entry cache;
  char *fname = "0123456789abcdef0123456789abcdef", *path;
  const char *contents = "<cacheEntry "
      "xmlns=\"http://uconn.edu/cas/mod_auth_cas\">"
      "<user>foo</user>"
      "<issued>86400</issued>"
      "<lastactive>87000</lastactive>"
      "<path>/foo</path>"
      "<ticket>ST-1234</ticket>"
      "<renewed />"
      "<secure />"
      "</cacheEntry>";

  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);

  c->CASCookiePath = "/tmp/";
  path = apr_pstrcat(request->pool, c->CASCookiePath, fname, NULL);
  apr_file_open(&f, path, APR_CREATE|APR_WRITE|APR_TRUNCATE, APR_OS_DEFAULT,
                request->pool);
  sz = strlen(contents);
  apr_file_write(f, contents, &sz);
  apr_file_close(f);

  readCASCacheFile(request, c, fname, &cache);

  fail_unless(strcmp(cache.user, "foo") == 0);
  fail_unless(cache.issued == 86400);
  fail_unless(cache.lastactive == 87000);
  fail_unless(strcmp(cache.path, "/foo") == 0);
  fail_unless(strcmp(cache.ticket, "ST-1234") == 0);
  fail_if(cache.renewed == FALSE);
  fail_if(cache.secure == FALSE);
  /* TODO(pames): test w/attributes */
  apr_file_remove(path, request->pool);
}
END_TEST

START_TEST(CASCleanCache_test) {
  fail();
}
END_TEST

START_TEST(writeCASCacheEntry_test) {
  apr_file_t *f;
  cas_cache_entry cache;
  char *fname = "fedcba9876543210fedcba9876543210", *path;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  c->CASCookiePath = "/tmp/";

  cache.user = "foo";
  cache.issued = 86400;
  cache.lastactive = 87000;
  cache.path = "/bar";
  cache.ticket = "ST-4321";
  cache.attrs = NULL;

  writeCASCacheEntry(request, fname, &cache, FALSE);

  path = apr_pstrcat(request->pool, c->CASCookiePath, fname, NULL);
  fail_if(apr_file_open(&f, path, APR_READ, APR_OS_DEFAULT, request->pool) !=
          APR_SUCCESS);
  /* TODO(pames): verify file contents. */
  /* TODO(pames): test w/attributes */
  apr_file_close(f);
  apr_file_remove(path, request->pool);
}
END_TEST

START_TEST(createCASCookie_test) {
  unsigned int i;
  char *path, *rv;
  char *ticket = "ST-ABCD";
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  c->CASCookiePath = "/tmp/";

  /* TODO(pames): const */
  rv = createCASCookie(request, "foo", NULL, ticket);

  path = apr_pstrcat(request->pool, c->CASCookiePath, rv, NULL);
  apr_file_remove(path, request->pool);

  for(i = 0; i < strlen(rv); i++) {
    if ((rv[i] < '0' || rv[i] > '9') &&
        (rv[i] < 'a' || rv[i] > 'f')) {
      fail();
    }
  }

  if (i != APR_MD5_DIGESTSIZE*2)
    fail();
}
END_TEST

START_TEST(expireCASST_test) {
  fail();
}
END_TEST

START_TEST(CASSAMLLogout_test) {
  fail();
}
END_TEST

START_TEST(deleteCASCacheFile_test) {
  fail();
}
END_TEST

char *get_attr(cas_cfg *c, cas_saml_attr *attrs, const char *attr) {
  cas_saml_attr_val *av = NULL;
  char *csvs = NULL;
  cas_saml_attr *a = NULL;
  for (a = attrs; a != NULL; a = a->next) {
    if (strcmp(a->attr, attr) != 0) continue;
    av = a->values;
    while (av != NULL) {
      if (csvs != NULL) {
        csvs = apr_psprintf(request->pool, "%s%s%s", csvs, c->CASAttributeDelimiter, av->value);
      } else {
        csvs = apr_psprintf(request->pool, "%s", av->value);
      }
      av = av->next;
    }
    break;
  }
  return csvs;
}

/*
 * CAS 3.5.1 switched from OpenSAML 1.1 to OpenSAML 2.x (https://issues.jasig.org/browse/CAS-951).
 *
 * OpenSAML 1.1 and 2.x produce slightly different XML structures, and old mod_auth_cas XML parsing
 * code did not work with 2.x.  Therefore, we now have two unit tests for the two different XML
 * structures: isValidCASTicket_OpenSAML1_test and isValidCASTicket_OpenSAML2_test
 */

/* Test OpenSAML 1.1 responses (CAS < 3.5.1) */
START_TEST(isValidCASTicket_OpenSAML1_test) {
  const char *response =
      "<?xml version='1.0' encoding='UTF-8'?>"
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'>"
      "<SOAP-ENV:Header/>"
      "<SOAP-ENV:Body>"
      "<Response xmlns='urn:oasis:names:tc:SAML:1.0:protocol'"
      " xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion'"
      " xmlns:samlp='urn:oasis:names:tc:SAML:1.0:protocol'"
      " xmlns:xsd='http://www.w3.org/2001/XMLSchema'"
      " xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
      " MajorVersion='1' MinorVersion='1'>"
      "<Status><StatusCode Value='samlp:Success'></StatusCode></Status>"
      "<Assertion xmlns='urn:oasis:names:tc:SAML:1.0:assertion' MajorVersion='1' MinorVersion='1'>"
      "<Conditions NotBefore='2011-01-01T12:00:00.000Z' NotOnOrAfter='2011-01-01T12:01:00.000Z'/>"
      "<AttributeStatement>"
      "<Subject><NameIdentifier>username</NameIdentifier></Subject>"
      "<Attribute AttributeName='FirstName'"
      " AttributeNamespace='http://www.ja-sig.org/products/cas/'>"
      "<AttributeValue>Joe</AttributeValue>"
      "</Attribute>"
      "<Attribute AttributeName='Last Name'"
      " AttributeNamespace='http://www.ja-sig.org/products/cas/'>"
      "<AttributeValue>Test</AttributeValue>"
      "</Attribute>"
      "<Attribute AttributeName='GroupList'"
      " AttributeNamespace='http://www.ja-sig.org/products/cas/'>"
      "<AttributeValue>A,B</AttributeValue>"
      "<AttributeValue>C</AttributeValue>"
      "</Attribute>"
      "</AttributeStatement>"
      "<AuthenticationStatement AuthenticationMethod='urn:oasis:names:tc:SAML:1.0:am:password'>"
      "<Subject><NameIdentifier>username</NameIdentifier></Subject>"
      "</AuthenticationStatement>"
      "</Assertion>"
      "</Response>"
      "</SOAP-ENV:Body>"
      "</SOAP-ENV:Envelope>";
  char *remoteUser = NULL;
  cas_saml_attr *attrs = NULL;
  char *attr;
  apr_byte_t rv;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  set_curl_response(response);
  c->CASCertificatePath = "/";
  c->CASValidateSAML = TRUE;
  rv = isValidCASTicket(request, c, "ST-1234", &remoteUser, &attrs);
  fail_if(rv == FALSE);
  attr = get_attr(c, attrs, "FirstName");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "Joe") == 0);
  attr = get_attr(c, attrs, "Last Name");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "Test") == 0);
  attr = get_attr(c, attrs, "GroupList");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "A,B" CAS_DEFAULT_ATTRIBUTE_DELIMITER "C") == 0);
  attr = get_attr(c, attrs, "AuthenticationMethod");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "urn:oasis:names:tc:SAML:1.0:am:password") == 0);
}
END_TEST

/* Test OpenSAML 2.x responses (CAS >= 3.5.1) */
START_TEST(isValidCASTicket_OpenSAML2_test) {
  const char *response =
      "<?xml version='1.0' encoding='UTF-8'?>"
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'>"
      "<SOAP-ENV:Body>"
      "<saml1p:Response xmlns:saml1p='urn:oasis:names:tc:SAML:1.0:protocol'"
      " IssueInstant='2011-01-01T01:01:01.001Z'"
      " MajorVersion='1' MinorVersion='1'"
      " Recipient='https://example.com/example_app'"
      " ResponseID='_0123456789abcdef0123456789abcdef'>"
      "<saml1p:Status><saml1p:StatusCode Value='saml1p:Success'/></saml1p:Status>"
      "<saml1:Assertion xmlns:saml1='urn:oasis:names:tc:SAML:1.0:assertion'"
      " AssertionID='_0123456789abcdef0123456789abcdef'"
      " IssueInstant='2011-01-01T01:01:01.001Z' Issuer='localhost'"
      " MajorVersion='1' MinorVersion='1'>"
      "<saml1:Conditions NotBefore='2011-01-01T12:00:00.000Z' NotOnOrAfter='2011-01-01T12:01:00.000Z'>"
      "<saml1:AudienceRestrictionCondition>"
      "<saml1:Audience>https://example.com/example_app</saml1:Audience>"
      "</saml1:AudienceRestrictionCondition>"
      "</saml1:Conditions>"
      "<saml1:AuthenticationStatement AuthenticationMethod='urn:oasis:names:tc:SAML:1.0:am:password'>"
      "<saml1:Subject><saml1:NameIdentifier>username</saml1:NameIdentifier></saml1:Subject>"
      "</saml1:AuthenticationStatement>"
      "<saml1:AttributeStatement>"
      "<saml1:Subject><saml1:NameIdentifier>username</saml1:NameIdentifier></saml1:Subject>"
      "<saml1:Attribute AttributeName='FirstName'"
      " AttributeNamespace='http://www.ja-sig.org/products/cas/'>"
      "<saml1:AttributeValue>Joe</saml1:AttributeValue>"
      "</saml1:Attribute>"
      "<saml1:Attribute AttributeName='Last Name'"
      " AttributeNamespace='http://www.ja-sig.org/products/cas/'>"
      "<saml1:AttributeValue>Test</saml1:AttributeValue>"
      "</saml1:Attribute>"
      "<saml1:Attribute AttributeName='GroupList'"
      " AttributeNamespace='http://www.ja-sig.org/products/cas/'>"
      "<saml1:AttributeValue>A,B</saml1:AttributeValue>"
      "<saml1:AttributeValue>C</saml1:AttributeValue>"
      "</saml1:Attribute>"
      "</saml1:AttributeStatement>"
      "</saml1:Assertion>"
      "</saml1p:Response>"
      "</SOAP-ENV:Body>"
      "</SOAP-ENV:Envelope>";
  char *remoteUser = NULL;
  cas_saml_attr *attrs = NULL;
  char *attr;
  apr_byte_t rv;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  set_curl_response(response);
  c->CASCertificatePath = "/";
  c->CASValidateSAML = TRUE;
  rv = isValidCASTicket(request, c, "ST-1234", &remoteUser, &attrs);
  fail_if(rv == FALSE);
  attr = get_attr(c, attrs, "FirstName");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "Joe") == 0);
  attr = get_attr(c, attrs, "Last Name");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "Test") == 0);
  attr = get_attr(c, attrs, "GroupList");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "A,B" CAS_DEFAULT_ATTRIBUTE_DELIMITER "C") == 0);
  attr = get_attr(c, attrs, "AuthenticationMethod");
  fail_if(attr == NULL);
  fail_unless(strcmp(attr, "urn:oasis:names:tc:SAML:1.0:am:password") == 0);
}
END_TEST

/* Test retrieving the user(name) from the AuthenticationStatement */
START_TEST(isValidCASTicket_username_in_AuthenticationStatement) {
  const char *response =
      "<?xml version='1.0' encoding='UTF-8'?>"
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'>"
      "<SOAP-ENV:Body>"
      "<saml1p:Response xmlns:saml1p='urn:oasis:names:tc:SAML:1.0:protocol'"
      " IssueInstant='2011-01-01T01:01:01.001Z'"
      " MajorVersion='1' MinorVersion='1'"
      " Recipient='https://example.com/example_app'"
      " ResponseID='_0123456789abcdef0123456789abcdef'>"
      "<saml1p:Status><saml1p:StatusCode Value='saml1p:Success'/></saml1p:Status>"
      "<saml1:Assertion xmlns:saml1='urn:oasis:names:tc:SAML:1.0:assertion'"
      " AssertionID='_0123456789abcdef0123456789abcdef'"
      " IssueInstant='2011-01-01T01:01:01.001Z' Issuer='localhost'"
      " MajorVersion='1' MinorVersion='1'>"
      "<saml1:Conditions NotBefore='2011-01-01T12:00:00.000Z' NotOnOrAfter='2011-01-01T12:01:00.000Z'>"
      "<saml1:AudienceRestrictionCondition>"
      "<saml1:Audience>https://example.com/example_app</saml1:Audience>"
      "</saml1:AudienceRestrictionCondition>"
      "</saml1:Conditions>"
      "<saml1:AuthenticationStatement AuthenticationMethod='urn:oasis:names:tc:SAML:1.0:am:password'>"
      "<saml1:Subject><saml1:NameIdentifier>username</saml1:NameIdentifier></saml1:Subject>"
      "</saml1:AuthenticationStatement>"
      "</saml1:Assertion>"
      "</saml1p:Response>"
      "</SOAP-ENV:Body>"
      "</SOAP-ENV:Envelope>";
  char *remoteUser = NULL;
  cas_saml_attr *attrs = NULL;
  apr_byte_t rv;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  set_curl_response(response);
  c->CASCertificatePath = "/";
  c->CASValidateSAML = TRUE;
  rv = isValidCASTicket(request, c, "ST-1234", &remoteUser, &attrs);
  fail_if(rv == FALSE);
  fail_if(remoteUser == NULL);
  fail_unless(strcmp(remoteUser, "username") == 0);
}
END_TEST

START_TEST(isValidCASCookie_test) {
  fail();
}
END_TEST

START_TEST(cas_curl_write_test) {
  cas_curl_buffer cb;
  const char *data = "This is some test data.";
  memset(&cb, 0, sizeof(cb));
  cas_curl_write(data, sizeof(char), sizeof(char)*strlen(data), &cb);

  fail_unless(strcmp(cb.buf, data) == 0);
  fail_unless(cb.written == strlen(data));
}
END_TEST

START_TEST(cas_curl_ssl_ctx_test) {
  fail();
}
END_TEST

START_TEST(getResponseFromServer_test) {
  const char *response = "<cas:serviceResponse xmlns:cas="
      "'http://www.yale.edu/tp/cas'>"
      "<cas:authenticationSuccess>"
      "<cas:user>username</cas:user>"
      "</cas:authenticationSuccess>"
      "</cas:serviceResponse>";
  char *rv;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  set_curl_response(response);
  rv = getResponseFromServer(request, c, "ST-1234");
#ifndef DARWIN
  // apr_stat behaves oddly while the tests are running (but works
  // just fine on a standalone test program).  It almost looks
  // like it doesn't get called at all, which results in NULL
  // being returned from getResponseFromServer.  In any case, the
  // code in getResponseFromServer needs to be refactored anyway,
  // so improving the test quality and getting it to work on OS X
  // can be saved for that date.
  fail_if(rv == NULL, apr_psprintf(request->pool,
      "getResponseFromServer() returned NULL\n"
      "  (Does %s (CAS_DEFAULT_CA_PATH in mod_auth_cas.h) exist?)",
      c->CASCertificatePath));
  fail_unless(strcmp(rv, response) == 0);
#endif
}
END_TEST

START_TEST(cas_authenticate_test) {
  fail();
}
END_TEST

START_TEST(cas_ssl_locking_callback_test) {
  fail();
}
END_TEST

START_TEST(cas_ssl_id_callback_test) {
#ifdef OPENSSL_NO_THREADID
  unsigned long tid = apr_os_thread_current();
  fail_unless(tid == cas_ssl_id_callback());
#endif
  // TODO(pames): handle the 'else' directive

}
END_TEST

START_TEST(cas_cleanup_test) {
  fail();
}
END_TEST

START_TEST(check_vhost_config_test) {
  fail();
}
END_TEST

START_TEST(check_merged_vhost_configs_test) {
  fail();
}
END_TEST

START_TEST(merged_vhost_configs_exist_test) {
  fail();
}
END_TEST

START_TEST(cas_post_config_test) {
  fail();
}
END_TEST

START_TEST(cas_in_filter_test) {
  fail();
}
END_TEST

START_TEST(cas_register_hooks_test) {
  fail();
}
END_TEST

#if MODULE_MAGIC_NUMBER_MAJOR < 20120211
START_TEST(cas_attribute_authz_test) {
  int should_fail1, should_fail2, should_succeed1, should_succeed2,
      should_succeed3, should_succeed4, should_succeed5, should_decline1,
      should_decline2;
  cas_saml_attr *attrs = NULL;
  cas_attr_builder *builder;
  require_line require_line_array[5];
  cas_cfg *c;
  int i;
  require_line *r;

  const char *old_method;
  int old_method_number;

  /* Manually create some SAML attributes.  These attributes represent
   * a CAS attribute payload returned by CAS.  This test will apply an
   * authorization policy to these attributes to test its behavior.
   */
  struct test_data {
      const char *const k;
      const char *const v;
  } test_data_list[] = {
      {"key1", "val1"},
      {"key1", "val2"},
      {"key2", "val3"},
      {"should", "succeed"},
      {"regexAttribute", "urn:mace:example.edu:testing?placeholder=there&success=true"},
      {0, 0} /* NULL terminator */
  };

  // Build a CAS attribute structure.
  builder = cas_attr_builder_new(pool, &attrs);
  i = 0;
  while (1) {
      struct test_data d = test_data_list[i];
      if (d.v == NULL) break;

      cas_attr_builder_add(builder, d.k, d.v);
      i++;
  }

  c = ap_get_module_config(request->server->module_config,
                           &auth_cas_module);

  /* Allow these tests to pass - simulate a GET request. */
  old_method = request->method;
  old_method_number = request->method_number;
  request->method = "GET";
  request->method_number = M_GET;

  /* Create 'Require' config structures representing the
   * configured authorization policy.  Although we create many, we'll
   * apply different combinations of them in the tests which
   * follow. */
  r = &(require_line_array[0]);
  r->method_mask = AP_METHOD_BIT;
  r->requirement = apr_pstrdup(pool, "cas-attribute hopefully:fail");

  r = &(require_line_array[1]);
  r->method_mask = AP_METHOD_BIT;
  r->requirement = apr_pstrdup(pool, "cas-attribute should:succeed");

  r = &(require_line_array[2]);
  r->method_mask = AP_METHOD_BIT;
  r->requirement = apr_pstrdup(pool, "cas-attribute regexAttribute~.+:testing\?.*success=true.*");

  r = &(require_line_array[3]);
  r->method_mask = AP_METHOD_BIT;
  r->requirement = apr_pstrdup(pool, "cas-attribute regexAttribute~.+:testing\?.*success=TRUE.*");

  r = &(require_line_array[4]);
  r->method_mask = AP_METHOD_BIT;
  r->requirement = apr_pstrdup(pool, "cas-attribute regexAttribute~.+:testing\?.*(?i:success=TRUE).*");

  /* When mod_auth_cas is authoritative, an attribute payload which
   * fails to pass the policy check should result in
   * HTTP_UNAUTHORIZED. */
  c->CASAuthoritative = 1;
  should_fail1 = cas_authorize_worker(request, attrs, &(require_line_array[0]), 1, c);
  c->CASAuthoritative = 1;
  should_fail2 = cas_authorize_worker(request, attrs, &(require_line_array[3]), 1, c);

  /* When mod_auth_cas is authoritative, an attribute payload which
   * does pass the policy check should succeed. */
  c->CASAuthoritative = 1;
  should_succeed1 = cas_authorize_worker(request, attrs, &(require_line_array[1]), 1, c);
  c->CASAuthoritative = 1;
  should_succeed2 = cas_authorize_worker(request, attrs, &(require_line_array[2]), 1, c);

  /* When mod_auth_cas is *not* authoritative, an attribute payload
   * which does pass the policy check should succeed. */
  c->CASAuthoritative = 0;
  should_succeed3 = cas_authorize_worker(request, attrs, &(require_line_array[0]), 2, c);
  c->CASAuthoritative = 0;
  should_succeed4 = cas_authorize_worker(request, attrs, &(require_line_array[2]), 1, c);

  /* Case-insensitive flag should allow case-sensitivity to be overridden */
  c->CASAuthoritative = 0;
  should_succeed5 = cas_authorize_worker(request, attrs, &(require_line_array[4]), 1, c);

  /* Regardless of whether mod_auth_cas is authoritative, the empty
   * list of Require directives means mod_auth_cas has no policy to
   * check and should DECLINE. */
  c->CASAuthoritative = 1;
  should_decline1 = cas_authorize_worker(request, attrs, NULL, 0, c);
  c->CASAuthoritative = 0;
  should_decline2 = cas_authorize_worker(request, attrs, NULL, 0, c);

  /* Restore the request object */
  request->method = old_method;
  request->method_number = old_method_number;

  fail_unless((should_fail1 == HTTP_UNAUTHORIZED) &&
              (should_fail2 == HTTP_UNAUTHORIZED) &&
              (should_succeed1 == OK) &&
              (should_succeed2 == OK) &&
              (should_succeed3 == OK) &&
              (should_succeed4 == OK) &&
              (should_succeed5 == OK) &&
              (should_decline1 == DECLINED) &&
              (should_decline2 == DECLINED));
}
END_TEST

#else

START_TEST(cas_attribute_authz_test) {
  int should_fail1, should_fail2, should_fail3 ,should_fail4 ,should_fail5 ,should_fail6, should_succeed1, should_succeed2,
      should_succeed3;
  cas_saml_attr *attrs = NULL;
  cas_attr_builder *builder;
  int i;

  const char *old_method;
  int old_method_number;

  /* Manually create some SAML attributes.  These attributes represent
   * a CAS attribute payload returned by CAS.  This test will apply an
   * authorization policy to these attributes to test its behavior.
   */
  struct test_data {
      const char *const k;
      const char *const v;
  } test_data_list[] = {
      {"key1", "val1"},
      {"key1", "val2"},
      {"key2", "val3"},
      {"should", "succeed"},
      {"regexAttribute", "urn:mace:example.edu:testing?placeholder=there&success=true"},
      {0, 0} /* NULL terminator */
  };

  const char *r[] = {
	  "hopefully:fail should:fail",
	  "hopefully:fail should:succeed",
	  "regexAttribute~.+:testing\?.*success=true.*",
	  "regexAttribute~.+:testing\?.*success=TRUE.*",
	  "regexAttribute~.+:testing\?.*(?i:success=TRUE).*",
	  "",
	  "novalue:",
	  ":noattribute",
	  "fail",
	  NULL
  };
  
  // Build a CAS attribute structure.
  builder = cas_attr_builder_new(pool, &attrs);
  i = 0;
  while (1) {
      struct test_data d = test_data_list[i];
      if (d.v == NULL) break;

      cas_attr_builder_add(builder, d.k, d.v);
      i++;
  }

  cas_set_attributes(request, attrs);
  
  /* Allow these tests to pass - simulate a GET request. */
  old_method = request->method;
  old_method_number = request->method_number;
  request->method = "GET";
  request->method_number = M_GET;

  should_fail1 = cas_check_authorization(request, r[0], (const void*)0);
  should_fail2 = cas_check_authorization(request, r[3], (const void*)0);
  should_fail3 = cas_check_authorization(request, r[5], (const void*)0);
  should_fail4 = cas_check_authorization(request, r[6], (const void*)0);
  should_fail5 = cas_check_authorization(request, r[7], (const void*)0);
  should_fail6 = cas_check_authorization(request, r[8], (const void*)0);

  should_succeed1 = cas_check_authorization(request, r[1], (const void*)0);
  should_succeed2 = cas_check_authorization(request, r[2], (const void*)0);
  should_succeed3 = cas_check_authorization(request, r[4], (const void*)0);

  /* Restore the request object */
  request->method = old_method;
  request->method_number = old_method_number;

  fail_unless((should_fail1 == AUTHZ_DENIED) &&
              (should_fail2 == AUTHZ_DENIED) &&
              (should_fail3 == AUTHZ_DENIED) &&
              (should_fail4 == AUTHZ_DENIED) &&
              (should_fail5 == AUTHZ_DENIED) &&
              (should_fail6 == AUTHZ_DENIED) &&
              (should_succeed1 == AUTHZ_GRANTED) &&
              (should_succeed2 == AUTHZ_GRANTED) &&
              (should_succeed3 == AUTHZ_GRANTED));
}
END_TEST

#endif


/* Generate a null-terminated string of random bytes between one and
 * length_limit characters */
char *rand_str(apr_pool_t *p, unsigned int length_limit) {
    /* Generate a random length from one to length_limit, inclusive.
     * This method for choosing a length is biased, but it should be
     * fine for testing purposes. */
    unsigned int len;
    char *ans;

    if (length_limit < 1) {
        len = 1;
    } else {
        apr_generate_random_bytes((unsigned char*)(&len), sizeof(unsigned int));
        len = abs(len) % length_limit;
    }
    /* Make room for the null terminator */
    len++;

    /* Generate a random, null-terminated sequence of bytes. The
     * terminator may appear earlier than the end, but we guarantee
     * that the string is terminated at or before length_limit
     * bytes. */
    ans = apr_palloc(p, len);
    apr_generate_random_bytes((unsigned char *) ans, len - 1);
    ans[len - 1] = '\0';
    return ans;
}

/* Macros for better output on cas_strnenvcmp test failures */
#define assert_snecmp_Xn(m,op,a,b,l) fail_unless(cas_strnenvcmp(a, b, l) op 0, \
                                                  apr_psprintf(p, "%s: <%s> <%s> %d", m, a, b, l))
#define assert_snecmp_eqn(a,b,l) assert_snecmp_Xn("Equal",==,a,b,l)
#define assert_snecmp_eq(a,b) assert_snecmp_eqn(a,b,-1)
#define assert_snecmp_ltn(a,b,l) assert_snecmp_Xn("Less than",<,a,b,l)
#define assert_snecmp_lt(a,b) assert_snecmp_ltn(a,b,-1)

START_TEST(cas_strnenvcmp_test) {
  /* Randomized tests: */
  int test_num;
  int num_tests = 100;
  apr_pool_t *p = request->pool;

  for (test_num = 0; test_num < num_tests; test_num++) {
    char *rnd1 = rand_str(p, test_num);
    char *rnd2 = rand_str(p, test_num);
    int l1 = strlen(rnd1);
    int l2 = strlen(rnd2);
    int l = l1 > l2 ? l1 : l2;
    int i;

    /* Comparing zero characters yields equal, regardless of the other
     * inputs. */
    assert_snecmp_eqn(rnd1, rnd2, 0);

    /* using length -1 is always the same as using the longer
     * length (this implies that the tests in the loop over
     * lengths don't need to explicitly test -1, since it's
     * equivalent) */
    fail_unless(cas_strnenvcmp(rnd1, rnd2, l) ==
                cas_strnenvcmp(rnd1, rnd2, -1));

    /* Strings of different length are ALWAYS unequal */
    fail_unless((l1 == l2) || cas_strnenvcmp(rnd1, rnd2, -1) != 0);

    /* For all lengths up to the length of the longer string */
    for (i = 0; i <= l; i++) {
      int a, b;

      /* A string always compares equal to itself */
      assert_snecmp_eqn(rnd1, rnd1, i);
      assert_snecmp_eqn(rnd2, rnd2, i);

      /* Swapping arguments flips the sign of the answer */
      a = cas_strnenvcmp(rnd1, rnd2, i);
      b = cas_strnenvcmp(rnd2, rnd1, i);
      fail_unless(((a == 0) && (b == 0))
                  || ((a < 0) && (b > 0))
                  || ((a > 0) && (b < 0)));
    }

  }

  /* Non-randomized tests */

  /* Empty string compares equal */
  assert_snecmp_eq("", "");

  /* Case-insensitivity */
  assert_snecmp_eq("AbC", "aBc");
  assert_snecmp_eq("foo", "FOO");
  assert_snecmp_eq("BaR", "bAR");

  /* Non-alphanumeric characters */
  assert_snecmp_eq("X-Y", "X_Y");
  assert_snecmp_eq("Ba-R", "bA_R");
  assert_snecmp_eq("Ba-R", "Ba-R");
  assert_snecmp_eq("%Ba-R", "_bA_R");
  assert_snecmp_eq("%Ba-R", "+bA_R");
  assert_snecmp_eq("%Ba-R", "\1bA_R");
  assert_snecmp_eq("%Ba-R", "\255bA_R");
  assert_snecmp_eq("Ba-R%", "bA_R\255");
  assert_snecmp_eq(" ", "-");
  assert_snecmp_eq("   ", "-  ");

  /* Simple sanity (sign of non-equal answer is correct). The other
   * cases (b first, both inputs same) are taken care of by the
   * randomized tests. */
  assert_snecmp_lt("a", "b");
  assert_snecmp_lt("A", "b");
  assert_snecmp_lt("a", "B");
  assert_snecmp_lt("A", "B");
  assert_snecmp_lt("_A", "-B");
  assert_snecmp_lt("a", "-");
  assert_snecmp_lt("A", "-");
  assert_snecmp_lt("A", "_");
  assert_snecmp_lt("a", "_");
  assert_snecmp_lt("a_", "b_");

  /* Simple equality/inequality */
  assert_snecmp_eq("012", "012");
  assert_snecmp_lt("XYZ", "ZYX");
  assert_snecmp_ltn("XYZ", "ZYX", 2);
  assert_snecmp_eqn("XY", "XYZ123", 2);
  assert_snecmp_ltn("XY", "XYZ123", 3);
  assert_snecmp_ltn("XY", "XYZ123", 100);
}
END_TEST

void core_setup(void) {
  const unsigned int kIdx = 0;
  const unsigned int kEls = kIdx + 1;
  cas_cfg *cfg = NULL;
  cas_dir_cfg *d_cfg = NULL;
  apr_uri_t login;
  request = (request_rec *) malloc(sizeof(request_rec));

  apr_pool_create(&pool, NULL);
  request->pool = pool;
  /* set up the request */
  request->headers_in = apr_table_make(request->pool, 0);
  request->headers_out = apr_table_make(request->pool, 0);
  request->err_headers_out = apr_table_make(request->pool, 0);

  apr_table_set(request->headers_in, "Host", "foo.example.com");
  apr_table_set(request->headers_in, "CAS_foo", "foo-value");
  apr_table_set(request->headers_in, "Cookie", "foo=bar; "
                CAS_DEFAULT_COOKIE "=0123456789abcdef; baz=zot");

  request->server = apr_pcalloc(request->pool,
                                sizeof(struct server_rec));
  request->connection = apr_pcalloc(request->pool, sizeof(struct conn_rec));
  request->connection->local_addr = apr_pcalloc(request->pool,
                                                sizeof(apr_sockaddr_t));


  apr_pool_userdata_set("https", "scheme", NULL, request->pool);
  request->server->server_hostname = "foo.example.com";
  request->connection->local_addr->port = 80;
  request->unparsed_uri = "/foo?bar=baz&zot=qux";
  request->uri = "/foo";
  request->args = "bar=baz&zot=qux";
  apr_uri_parse(request->pool, "http://foo.example.com/foo?bar=baz&zot=qux",
                &request->parsed_uri);

  /* set up the per server, and per directory configs */
  auth_cas_module.module_index = kIdx;
  cfg = cas_create_server_config(request->pool, request->server);
  cfg->CASDebug = TRUE;
  memset(&login, 0, sizeof(login));
  login.scheme = "https";
  login.hostname = "login.example.com";
  login.path = "/cas/login";
  login.port = 0;
  memcpy(&cfg->CASLoginURL, &login, sizeof(apr_uri_t));

  d_cfg = cas_create_dir_config(request->pool, NULL);

  request->request_config = apr_pcalloc(request->pool,
                                      sizeof(ap_conf_vector_t *)*kEls);  
  request->server->module_config = apr_pcalloc(request->pool,
                                               sizeof(ap_conf_vector_t *)*kEls);
  request->per_dir_config = apr_pcalloc(request->pool,
                                        sizeof(ap_conf_vector_t *)*kEls);
  ap_set_module_config(request->server->module_config, &auth_cas_module, cfg);
  ap_set_module_config(request->per_dir_config, &auth_cas_module, d_cfg);
}

void core_teardown(void) {
  // created by various cookie test functions above
  apr_file_remove("/tmp/.metadata", request->pool);
  apr_file_remove("/tmp/.md5", request->pool);
  /*
   * TODO(pames): figure out why one of these cookie/file-related tests creates
   * a /tmp/.md5 file in addition to the /tmp/.metadata file. and do the cleanup
   * there?
   */
  apr_pool_destroy(request->pool);
  free(request);
}

Suite *mod_auth_cas_suite(void) {
  Suite *s = suite_create("mod_auth_cas");

  TCase *tc_core = tcase_create("core");
  tcase_add_checked_fixture(tc_core, core_setup, core_teardown);
  tcase_add_test(tc_core, escapeString_test);
  tcase_add_test(tc_core, isSSL_test);
  tcase_add_test(tc_core, cas_char_to_env_test);
  tcase_add_test(tc_core, cas_scrub_headers_test);
  tcase_add_test(tc_core, cas_strnenvcmp_test);
  tcase_add_test(tc_core, normalizeHeaderName_test);
  tcase_add_test(tc_core, cas_merge_server_config_test);
  tcase_add_test(tc_core, cas_merge_dir_config_test);
  tcase_add_test(tc_core, cas_setURL_test);
  tcase_add_test(tc_core, getCASPath_test);
  tcase_add_test(tc_core, getCASScope_test);
  tcase_add_test(tc_core, getCASGatewayV1_test);
  tcase_add_test(tc_core, getCASGatewayV2_test);
  tcase_add_test(tc_core, getCASRenew_test);
  tcase_add_test(tc_core, getCASLoginURL_test);
  tcase_add_test(tc_core, getCASService_http_test);
  tcase_add_test(tc_core, getCASService_https_test);
  tcase_add_test(tc_core, getCASService_http_port_test);
  tcase_add_test(tc_core, getCASService_https_port_test);
  tcase_add_test(tc_core, getCASService_root_proxied_test);
  tcase_add_test(tc_core, getCASService_empty_qs_test);
  tcase_add_test(tc_core, redirectRequest_test);
  tcase_add_test(tc_core, removeCASParams_test);
  tcase_add_test(tc_core, validCASTicketFormat_test);
  tcase_add_test(tc_core, getCASTicket_test);
  tcase_add_test(tc_core, getCASCookie_test);
  tcase_add_test(tc_core, setCASCookie_test);
  tcase_add_test(tc_core, setCASCookieExpiryNow_test);
  tcase_add_test(tc_core, setCASCookieExpiryFiveSeconds_test);
  tcase_add_test(tc_core, getCASCookie_empty_test);
  tcase_add_test(tc_core, removeGatewayCookie_test);
  tcase_add_test(tc_core, urlEncode_test);
  tcase_add_test(tc_core, readCASCacheFile_test);
  tcase_add_test(tc_core, CASCleanCache_test);
  tcase_add_test(tc_core, writeCASCacheEntry_test);
  tcase_add_test(tc_core, createCASCookie_test);
  tcase_add_test(tc_core, expireCASST_test);
  tcase_add_test(tc_core, CASSAMLLogout_test);
  tcase_add_test(tc_core, deleteCASCacheFile_test);
  tcase_add_test(tc_core, getResponseFromServer_test);
  tcase_add_test(tc_core, isValidCASTicket_OpenSAML1_test);
  tcase_add_test(tc_core, isValidCASTicket_OpenSAML2_test);
  tcase_add_test(tc_core, isValidCASTicket_username_in_AuthenticationStatement);
  tcase_add_test(tc_core, isValidCASCookie_test);
  tcase_add_test(tc_core, cas_curl_write_test);
  tcase_add_test(tc_core, cas_curl_ssl_ctx_test);
  tcase_add_test(tc_core, cas_authenticate_test);
  tcase_add_test(tc_core, cas_ssl_locking_callback_test);
  tcase_add_test(tc_core, cas_ssl_id_callback_test);
  tcase_add_test(tc_core, cas_cleanup_test);
  tcase_add_test(tc_core, check_vhost_config_test);
  tcase_add_test(tc_core, check_merged_vhost_configs_test);
  tcase_add_test(tc_core, merged_vhost_configs_exist_test);
  tcase_add_test(tc_core, cas_post_config_test);
  tcase_add_test(tc_core, cas_in_filter_test);
  tcase_add_test(tc_core, cas_register_hooks_test);
  tcase_add_test(tc_core, cas_attribute_authz_test);
  suite_add_tcase(s, tc_core);
  suite_add_tcase(s, cas_saml_attr_tcase());

  return s;
}

int main (int argc, char *argv[]) {
  unsigned int number_failed;
  Suite *s;
  SRunner *sr;

  apr_app_initialize(&argc, (const char * const **) &argv, NULL);

  s = mod_auth_cas_suite();
  sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  apr_terminate();
  return (number_failed != 0);
}
