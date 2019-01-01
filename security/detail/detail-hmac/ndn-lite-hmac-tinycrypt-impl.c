
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

int ndn_lite_hmac_make_key_tinycrypt(ndn_hmac_key_t* key, uint32_t key_id,
                                     const uint8_t* input_value, uint32_t input_size,
                                     const uint8_t* personalization, uint32_t personalization_size,
                                     const uint8_t* seed_value, uint32_t seed_size,
                                     const uint8_t* additional_value, uint32_t additional_size,
                                     uint32_t salt_size)
{
  uint8_t salt[salt_size];
  int r = ndn_lite_random_hmacprng_tinycrypt(personalization, personalization_size, 
                                             salt, sizeof(salt), seed_value, seed_size, 
                                             additional_value, additional_size);

  if (r != NDN_SUCCESS) 
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  key->key_size = NDN_SEC_SHA256_HASH_SIZE;
  r = ndn_lite_random_hkdf_tinycrypt(input_value, input_size, key->key_value, key->key_size,
                                     salt, sizeof(salt));
  if (r != NDN_SUCCESS) 
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  key->key_id = key_id;
  return NDN_SUCCESS;           
}