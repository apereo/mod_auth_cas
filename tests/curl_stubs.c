#include <curl/curl.h>

CURL_EXTERN CURL *curl_easy_init(void) {
  return NULL;
}

CURL_EXTERN void curl_easy_cleanup(CURL *curl)
{
  return;
}

CURL_EXTERN CURLcode curl_easy_perform(CURL *curl) {

  return CURLE_OK;
}

/* This is an ugly hack to temporarily disable macro expansion. */
#pragma push_macro("curl_easy_setopt")
#undef curl_easy_setopt
CURL_EXTERN CURLcode curl_easy_setopt (CURL *curl, CURLoption option, ...) {
  return CURLE_OK;
}

#pragma pop_macro("curl_easy_setopt")

CURL_EXTERN void curl_global_cleanup(void) {
  return;
}

CURL_EXTERN CURLcode curl_global_init(long flags) {
  return CURLE_OK;
}

CURL_EXTERN struct curl_slist *curl_slist_append(struct curl_slist *list,
                                                 const char *append)
{
  return NULL;
}

CURL_EXTERN void curl_slist_free_all(struct curl_slist *list)
{
  return;
}
