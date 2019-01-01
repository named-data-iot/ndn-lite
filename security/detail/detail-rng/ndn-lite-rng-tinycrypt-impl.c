
#include "ndn-lite-rng-tinycrypt-impl.h"

#include "../detail-hmac/ndn-lite-hmac-tinycrypt-impl.h"

#include "../../../adaptation/ndn-nrf-ble-adaptation/logger.h"

#include "../../../ndn-constants.h"
#include "../../../ndn-error-code.h"

#include <stddef.h>

int ndn_lite_random_hkdf_tinycrypt(const uint8_t* input_value, uint32_t input_size,
                         uint8_t* output_value, uint32_t output_size,
                         const uint8_t* seed_value, uint32_t seed_size)
{
  uint8_t prk[NDN_SEC_SHA256_HASH_SIZE] = {0};
  if (ndn_lite_hmac_sha256_tinycrypt(input_value, input_size, 
                                     seed_value, seed_size, prk) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  //APP_LOG_HEX("Current value of prk:", prk, NDN_SEC_SHA256_HASH_SIZE);

  int iter;
  if (output_size % NDN_SEC_SHA256_HASH_SIZE)
    iter = output_size / NDN_SEC_SHA256_HASH_SIZE + 1;
  else
    iter = output_size / NDN_SEC_SHA256_HASH_SIZE;
  //APP_LOG("Value of iter: %d\n", iter);
  uint8_t t[NDN_SEC_SHA256_HASH_SIZE] = {0};
  uint8_t cat[NDN_SEC_SHA256_HASH_SIZE+1] = {0};
  uint8_t okm[NDN_SEC_SHA256_HASH_SIZE * iter];
  for (uint8_t i = 0; i < NDN_SEC_SHA256_HASH_SIZE * iter; i++)
    okm[i] = 0;
  uint8_t table[16] = {0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  uint8_t t_first[2] = {0x00, 0x01};
  //APP_LOG_HEX("Current value of okm (before for loop):", okm, NDN_SEC_SHA256_HASH_SIZE * iter);
  for (int i = 0; i < iter; ++i) {
    if (i == 0) {
      if (ndn_lite_hmac_sha256_tinycrypt(prk, NDN_SEC_SHA256_HASH_SIZE,
                                     t_first, sizeof(t_first), t) != NDN_SUCCESS) {
        return NDN_SEC_CRYPTO_ALGO_FAILURE;
      }
      memcpy(okm + i * NDN_SEC_SHA256_HASH_SIZE, t, NDN_SEC_SHA256_HASH_SIZE);
      //APP_LOG_HEX("Current value of okm (within for loop):", okm, NDN_SEC_SHA256_HASH_SIZE * iter);
    }
    else {
      memcpy(cat, t, NDN_SEC_SHA256_HASH_SIZE);
      cat[NDN_SEC_SHA256_HASH_SIZE] = table[i];
      if (ndn_lite_hmac_sha256_tinycrypt(prk, NDN_SEC_SHA256_HASH_SIZE,
                                      cat, NDN_SEC_SHA256_HASH_SIZE+1, t) != NDN_SUCCESS) {
        return NDN_SEC_CRYPTO_ALGO_FAILURE;
      }
      memcpy(okm + i * NDN_SEC_SHA256_HASH_SIZE, t, NDN_SEC_SHA256_HASH_SIZE);
      //APP_LOG_HEX("Current value of okm (within for loop):", okm, NDN_SEC_SHA256_HASH_SIZE * iter);
    }
  }
  memcpy(output_value, okm, output_size);
  //APP_LOG_HEX("Current value of okm (end):", okm, NDN_SEC_SHA256_HASH_SIZE * iter);
  return NDN_SUCCESS;
}
