#include <check.h>
#include <stdio.h>

#include <apr.h>
#include <apr_general.h>
#include <apr_portable.h>

#include <httpd.h>
#include <http_config.h>
#include <util_filter.h>
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
  fail();
}
END_TEST

START_TEST(getCASService_test) {
  fail();
}
END_TEST

START_TEST(redirectRequest_test) {
  fail();
}
END_TEST

START_TEST(removeCASParams_test) {
  fail();
}
END_TEST

START_TEST(getCASTicket_test) {
  fail();
}
END_TEST

START_TEST(getCASCookie_test) {
  fail();
}
END_TEST

START_TEST(setCASCookie_test) {
  fail();
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
  fail();
}
END_TEST

START_TEST(CASCleanCache_test) {
  fail();
}
END_TEST

START_TEST(writeCASCacheEntry_test) {
  fail();
}
END_TEST

START_TEST(createCASCookie_test) {
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
  fail();
}
END_TEST

START_TEST(cas_curl_ssl_ctx_test) {
  fail();
}
END_TEST

START_TEST(getResponseFromServer_test) {
  fail();
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
  request = (request_rec *) malloc(sizeof(request_rec));

  apr_pool_create(&pool, NULL);
  request->pool = pool;
  /* set up the request */
  request->server = apr_pcalloc(request->pool,
                                sizeof(struct server_rec));


  /* set up the per server, and per directory configs */
  auth_cas_module.module_index = kIdx;
  cas_cfg *cfg = cas_create_server_config(request->pool, request->server);
  cfg->CASDebug = TRUE;
  cas_dir_cfg *d_cfg = cas_create_dir_config(request->pool, NULL);

  request->server->module_config = apr_pcalloc(request->pool,
                                               sizeof(ap_conf_vector_t *)*kEls);
  request->per_dir_config = apr_pcalloc(request->pool,
                                        sizeof(ap_conf_vector_t *)*kEls);
  ap_set_module_config(request->server->module_config, &auth_cas_module, cfg);
  ap_set_module_config(request->per_dir_config, &auth_cas_module, d_cfg);
}

void core_teardown() {
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
  tcase_add_test(tc_core, getCASService_test);
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
