#include <check.h>
#include <stdio.h>

#include <apr.h>
#include <apr_general.h>

#include <httpd.h>
#include <http_config.h>
#include <util_filter.h>
#include <mod_include.h>

#include "../src/mod_auth_cas.h"

request_rec *request;
apr_pool_t *pool;

START_TEST (urlencode) {
  char *rv;
  rv = escapeString(request, "a b");
  fail_unless(strcmp(rv, "a%%20b") == 0);
}
END_TEST

void core_setup() {
  request = (request_rec *) malloc(sizeof(request_rec));
  apr_pool_create(&pool, NULL);
  request->pool = pool;
}

void core_teardown() {
  apr_pool_destroy(request->pool);
  free(request);
}

Suite *mod_auth_cas_suite() {
  Suite *s = suite_create("mod_auth_cas");

  TCase *tc_core = tcase_create("core");
  tcase_add_checked_fixture(tc_core, core_setup, core_teardown);
  tcase_add_test(tc_core, urlencode);
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
