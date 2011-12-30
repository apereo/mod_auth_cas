
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "util_filter.h"
#include "util_md5.h"


/* there seems to be no function protoype for this */
const char *ap_run_http_scheme(const request_rec *r);
/* ridiculous prototype for AP_DECLARE_HOOK entries */
void ap_hook_check_user_id(int (*)(request_rec *),
				const char * const *,
				const char * const *,
				int);

AP_DECLARE(ap_filter_t *) ap_add_input_filter(const char *name, void *ctx,
                                              request_rec *r, conn_rec *c) {

  return NULL;
}

AP_DECLARE(const char *) ap_auth_type(request_rec *r) {
  return "CAS";
}

AP_DECLARE(apr_status_t) ap_get_brigade(ap_filter_t *filter,
                                        apr_bucket_brigade *bucket, 
                                        ap_input_mode_t mode,
                                        apr_read_type_e block, 
                                        apr_off_t readbytes) {
  return APR_EGENERAL;
}

AP_DECLARE(char *) ap_getword(apr_pool_t *p, const char **line, char stop) {

  return "";
}


void ap_hook_check_user_id(int (*pf)(request_rec *),
				const char * const *c1,
				const char * const *c2,
				int nOrder) {
	return;
}

AP_DECLARE(int) ap_is_initial_req(request_rec *r) {
  return 0;
}

AP_DECLARE(void) ap_log_error(const char *file, int line, int level, 
                              apr_status_t status, const server_rec *s,
                              const char *fmt, ...) {

}

AP_DECLARE(void) ap_log_rerror(const char *file, int line, int level, 
                              apr_status_t status, const request_rec *s,
                              const char *fmt, ...) {

}

AP_DECLARE(char *) ap_md5_binary(apr_pool_t *a, const unsigned char *buf,
                                 int len)
{

  return "md5";
}

APR_HOOK_STRUCT(APR_HOOK_LINK(post_config))
AP_IMPLEMENT_HOOK_RUN_ALL(int, post_config,
                          (apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp, server_rec *s),
                          (pconf, plog, ptemp, s), OK, DECLINED)

AP_DECLARE(ap_filter_rec_t *) ap_register_input_filter(const char *name,
                                                       ap_in_filter_func
                                                       filter_func,
                                                       ap_init_filter_func
                                                       filter_init,
                                                       ap_filter_type ftype) {
  return NULL;
}

const char *ap_run_http_scheme(const request_rec *r) {
  char *rv;
  apr_pool_userdata_get((void **) &rv, "scheme", r->pool); 
  return (const char *) rv;
}

AP_DECLARE_NONSTD(const char *) ap_set_string_slot(cmd_parms *cmd,
                                                   void *struct_ptr,
                                                   const char *arg) {

  return "";
}

AP_DECLARE(int) ap_unescape_url(char *url) {

  return 0;
}
