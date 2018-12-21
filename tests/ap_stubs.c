
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "util_filter.h"
#include <ctype.h>
#include "util_md5.h"

/* there seems to be no function protoype for this */
const char *ap_run_http_scheme(const request_rec *r);
/* ridiculous prototype for AP_DECLARE_HOOK entries */
void ap_hook_check_user_id(int (*)(request_rec *),
				const char * const *,
				const char * const *,
				int);

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

#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211

AP_DECLARE(void) ap_log_error_(const char *file, int line, int module_index,
                               int level, apr_status_t status,
                               const server_rec *s, const char *fmt, ...) {
}

AP_DECLARE(void) ap_log_rerror_(const char *file, int line, int module_index,
                                int level, apr_status_t status,
                                const request_rec *r, const char *fmt, ...) {
}
#else

AP_DECLARE(void) ap_log_error(const char *file, int line, int level,
                              apr_status_t status, const server_rec *s,
                              const char *fmt, ...) {

}

AP_DECLARE(void) ap_log_rerror(const char *file, int line, int level,
                              apr_status_t status, const request_rec *s,
                              const char *fmt, ...) {

}
#endif

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

void ap_hook_auth_checker(int (*pf)(request_rec *),
                          const char * const *c1,
                          const char * const *c2,
                          int nOrder) {
}

/* Perhaps this is the top of a slippery slope, but pulling these in
 * allowed us to test most of the authz functions fairly thoroughly.
 */
#define apr_isspace(c) (isspace(((unsigned char)(c))))

AP_DECLARE(char *) ap_getword_white(apr_pool_t *p, const char **line) {

    const char *pos = *line;
    int len;
    char *res;

    while (!apr_isspace(*pos) && *pos) {
        ++pos;
    }

    len = pos - *line;
    res = calloc(1, len + 1);
    memcpy(res, *line, len);
    res[len] = 0;

    while (apr_isspace(*pos)) {
        ++pos;
    }

    *line = pos;

    return res;
}

static char *substring_conf(apr_pool_t *p, const char *start, int len,                                 
                            char quote)
{
    char *result = calloc(sizeof(char), len + 2);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
        if (start[i] == '\\' && (start[i + 1] == '\\'
                                 || (quote && start[i + 1] == quote)))
            *resp++ = start[++i];
        else
            *resp++ = start[i];
    }

    *resp++ = '\0';
    return result;
}

AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line) {

    const char *str = *line, *strend;
    char *res;
    char quote;

    while (*str && apr_isspace(*str))
        ++str;

    if (!*str) {
        *line = str;
        return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
        strend = str + 1;
        while (*strend && *strend != quote) {
            if (*strend == '\\' && strend[1] &&
                (strend[1] == quote || strend[1] == '\\')) {
                strend += 2;
            }
            else {
                ++strend;
            }
        }
        res = substring_conf(p, str + 1, strend - str - 1, quote);

        if (*strend == quote)
            ++strend;
    }
    else {
        strend = str;
        while (*strend && !apr_isspace(*strend))
            ++strend;

        res = substring_conf(p, str, strend - str, 0);
    }

    while (*strend && apr_isspace(*strend))
        ++strend;
    *line = strend;
    return res;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20120211

AP_DECLARE(void) ap_hook_check_access(ap_HOOK_access_checker_t *pf,
                                      const char * const *aszPre,
                                      const char * const *aszSucc,
                                      int nOrder, int type) {
}

AP_DECLARE(void) ap_hook_check_authn(ap_HOOK_access_checker_t *pf,
                                     const char * const *aszPre,
                                     const char * const *aszSucc,
                                     int nOrder, int type) {
}

AP_DECLARE(apr_status_t) ap_register_auth_provider(apr_pool_t *pool,
                                                   const char *provider_group,
                                                   const char *provider_name,
                                                   const char *provider_version,
                                                   const void *provider,
                                                   int type) {
  return APR_SUCCESS;
}
#else

AP_DECLARE(void) ap_note_auth_failure(request_rec *r) {

  return;
}

AP_DECLARE(const apr_array_header_t *) ap_requires(request_rec *r) {

  return NULL;
}
#endif
