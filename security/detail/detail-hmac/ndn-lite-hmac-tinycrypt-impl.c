
#include "ndn-lite-hmac-tinycrypt-impl.h"

#include "../sec-lib/tinycrypt/tc_hmac.h"
#include "../sec-lib/tinycrypt/tc_constants.h"
#include "../../../../ndn-error-code.h"
#include "../../../../ndn-constants.h"

#include <string.h>

int ndn_lite_hmac_sha256_tinycrypt(const uint8_t* key, unsigned int key_size,
                                   const void* data, unsigned int data_length,
                                   uint8_t* hmac_result) {
  struct tc_hmac_state_struct h;
  (void)memset(&h, 0x00, sizeof(h));
  if (tc_hmac_set_key(&h, key, key_size) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_hmac_init(&h) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_hmac_update(&h, data, data_length) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_hmac_final(hmac_result, TC_SHA256_DIGEST_SIZE, &h) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
}