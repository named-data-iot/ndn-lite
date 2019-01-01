
#include "ndn-lite-sha256-tinycrypt-impl.h"

#include "../../../../ndn-error-code.h"
#include "../sec-lib/tinycrypt/tc_sha256.h"
#include "../sec-lib/tinycrypt/tc_constants.h"

int ndn_lite_sha256_tinycrypt(const uint8_t* data, size_t datalen, uint8_t* hash_result)
{
  struct tc_sha256_state_struct s;
  if (tc_sha256_init(&s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_sha256_update(&s, data, datalen) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_INIT_FAILURE;
  }
  if (tc_sha256_final(hash_result, &s) != TC_CRYPTO_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return NDN_SUCCESS;
}