#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
unsigned long (*CRYPTO_get_id_callback(void))(void) {

  return 0L;
}

void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
                                          int line) {
  return NULL;
}

int CRYPTO_num_locks(void) {

  return 0;
}

void CRYPTO_set_id_callback(unsigned long (*func)(void)) {

}

void CRYPTO_set_locking_callback(void (*func)(int mode,int type, const char
                                              *file,int line))
{
  return;
}
#endif

void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth) {
  return;
}
