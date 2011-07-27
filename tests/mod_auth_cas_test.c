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

request_rec *request;
apr_pool_t *pool;


START_TEST(cas_merge_server_config_test) {
  cas_cfg *base = cas_create_server_config(request->pool, NULL);
  cas_cfg *add = cas_create_server_config(request->pool, NULL);
  cas_cfg *merged;
  apr_uri_t uri;

  fail_if(base->merged == TRUE);
  fail_if(add->merged == TRUE);

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
  cas_dir_cfg *base = cas_create_dir_config(request->pool, NULL);
  cas_dir_cfg *add = cas_create_dir_config(request->pool, NULL);
  
  add->CASCookie = "XYZ";
  cas_dir_cfg *merged = (cas_dir_cfg *) cas_merge_dir_config(request->pool,
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

START_TEST (isSSL_test) {
  /* stuff state into an arbitrary place in the pool */
  apr_pool_userdata_set("https", "scheme", NULL, request->pool);
  fail_unless(isSSL(request) == TRUE);
  apr_pool_userdata_set("http", "scheme", NULL, request->pool);
  fail_unless(isSSL(request) == FALSE);
}
END_TEST

START_TEST(getCASPath_test) {
  char *path;
  apr_uri_parse(request->pool, "http://www.example.com/foo/bar/baz.html",
                &request->parsed_uri);

  path = getCASPath(request);
  fail_unless(strcmp(path, "/foo/bar/") == 0);
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
  char *args = "foo=bar&ticket=ST-1234&baz=zot";
  const char *expected = "foo=bar&baz=zot";

  request->args = apr_pstrdup(request->pool, args);
  fail_if(removeCASParams(request) == FALSE);
  fail_unless(strcmp(request->args, expected) == 0);

  args = "foo=bar&ticket=not-expected-format&baz=zot";
  request->args = apr_pstrdup(request->pool, args);
  fail_if(removeCASParams(request) == TRUE);
  fail_unless(strcmp(request->args, args) == 0);

}
END_TEST

START_TEST(getCASTicket_test) {
  char *args = "foo=bar&ticket=ST-1234&baz=zot", *rv;
  const char *expected = "ST-1234";
  request->args = apr_pstrdup(request->pool, args);
  rv = getCASTicket(request);
  fail_unless(strcmp(rv, expected) == 0);
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
  setCASCookie(request, "cookie_name", "cookie_value", FALSE);
  rv = apr_table_get(request->err_headers_out, "Set-Cookie");
  fail_unless(strcmp(rv, expected) == 0);

  /* TODO(pames): test with CASRootProxiedAs */
  /* TODO(pames): test with secure, domain, httponly, a specific path... */
}
END_TEST

START_TEST (escapeString_test) {
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

START_TEST(isValidCASTicket_test) {
  fail();
}
END_TEST

START_TEST(isValidCASCookie_test) {
  fail();
}
END_TEST

START_TEST(cas_curl_write_test) {
  cas_curl_buffer cb;
  memset(&cb, 0, sizeof(cb));
  const char *data = "This is some test data.";
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
  const char *expected = "<cas:serviceResponse xmlns:cas="
      "'http://www.yale.edu/tp/cas'>"
      "<cas:authenticationSuccess>"
      "<cas:user>username</cas:user>"
      "</cas:authenticationSuccess>"
      "</cas:serviceResponse>";
  char *rv;
  cas_cfg *c = ap_get_module_config(request->server->module_config,
                                    &auth_cas_module);
  rv = getResponseFromServer(request, c, "ST-1234");
  fail_unless(strcmp(rv, expected) == 0);
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

void core_setup() {
  const unsigned int kIdx = 0;
  const unsigned int kEls = kIdx + 1;
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
  request->args = "bar=baz&zot=qux";
  apr_uri_parse(request->pool, "http://foo.example.com/foo?bar=baz&zot=qux",
                &request->parsed_uri);
 
  /* set up the per server, and per directory configs */
  auth_cas_module.module_index = kIdx;
  cas_cfg *cfg = cas_create_server_config(request->pool, request->server);
  cfg->CASDebug = TRUE;
  login.scheme = "https";
  login.hostname = "login.example.com";
  login.path = "/cas/login";
  memcpy(&cfg->CASLoginURL, &login, sizeof(apr_uri_t));

  cas_dir_cfg *d_cfg = cas_create_dir_config(request->pool, NULL);

  request->server->module_config = apr_pcalloc(request->pool,
                                               sizeof(ap_conf_vector_t *)*kEls);
  request->per_dir_config = apr_pcalloc(request->pool,
                                        sizeof(ap_conf_vector_t *)*kEls);
  ap_set_module_config(request->server->module_config, &auth_cas_module, cfg);
  ap_set_module_config(request->per_dir_config, &auth_cas_module, d_cfg);
}

void core_teardown() {
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

Suite *mod_auth_cas_suite() {
  Suite *s = suite_create("mod_auth_cas");

  TCase *tc_core = tcase_create("core");
  tcase_add_checked_fixture(tc_core, core_setup, core_teardown);
  tcase_add_test(tc_core, escapeString_test);
  tcase_add_test(tc_core, isSSL_test);
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
  tcase_add_test(tc_core, redirectRequest_test);
  tcase_add_test(tc_core, removeCASParams_test);
  tcase_add_test(tc_core, getCASTicket_test);
  tcase_add_test(tc_core, getCASCookie_test);
  tcase_add_test(tc_core, setCASCookie_test);
  tcase_add_test(tc_core, urlEncode_test);
  tcase_add_test(tc_core, readCASCacheFile_test);
  tcase_add_test(tc_core, CASCleanCache_test);
  tcase_add_test(tc_core, writeCASCacheEntry_test);
  tcase_add_test(tc_core, createCASCookie_test);
  tcase_add_test(tc_core, expireCASST_test);
  tcase_add_test(tc_core, CASSAMLLogout_test);
  tcase_add_test(tc_core, deleteCASCacheFile_test);
  tcase_add_test(tc_core, isValidCASTicket_test);
  tcase_add_test(tc_core, isValidCASCookie_test);
  tcase_add_test(tc_core, cas_curl_write_test);
  tcase_add_test(tc_core, cas_curl_ssl_ctx_test);
  tcase_add_test(tc_core, getResponseFromServer_test);
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
  suite_add_tcase(s, tc_core);

  return s;
}

int main (int argc, char *argv[]) {
  unsigned int number_failed;

  apr_app_initialize(&argc, (const char * const **) &argv, NULL);

  Suite *s = mod_auth_cas_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  apr_terminate();
  return (number_failed != 0);
}
