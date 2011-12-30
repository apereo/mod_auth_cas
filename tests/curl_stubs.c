#include <curl/curl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "curl_stubs.h"

typedef struct curl_stub {
  void *data;
  size_t (*writefunc)(void *, size_t, size_t, void*);
} curl_stub;

static const char *curl_response = NULL;

void set_curl_response(const char *response) {
  curl_response = response;
}

CURL_EXTERN CURL *curl_easy_init(void) {
  CURL *rv = (CURL *) malloc(sizeof(curl_stub));
  return rv;
}

CURL_EXTERN void curl_easy_cleanup(CURL *curl)
{
  free(curl);
}

CURL_EXTERN CURLcode curl_easy_perform(CURL *curl) {
  curl_stub *c = (curl_stub *) curl;
  c->writefunc((void *)curl_response, sizeof(char), strlen(curl_response), c->data);

  return CURLE_OK;
}

/* This is an ugly hack to temporarily disable macro expansion. */
#pragma push_macro("curl_easy_setopt")
#undef curl_easy_setopt
CURL_EXTERN CURLcode curl_easy_setopt (CURL *curl, CURLoption option, ...) {
  curl_stub *cs = (curl_stub *) curl;
  void *arg;
  va_list args;
  va_start(args, option);
  arg = va_arg(args, void *);
  va_end(args);
  switch (option) {
    case CURLOPT_WRITEDATA:
      cs->data = arg;
      break;
    case CURLOPT_WRITEFUNCTION:
      cs->writefunc = arg;
      break;
    default:
      break;
  }
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
