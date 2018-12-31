
#include "ndn-lite-aes-tinycript-impl.h"

#include "../sec-lib/tinycrypt/tc_cbc_mode.h"
#include "../sec-lib/tinycrypt/tc_constants.h"
#include "../../../../ndn-error-code.h"
#include "../../../../ndn-constants.h"

int ndn_lite_aes_cbc_encrypt_tinycript(const uint8_t* input_value, uint8_t input_size,
                                                  uint8_t* output_value, uint8_t output_size,
                                                  const uint8_t* aes_iv,
                                                  const uint8_t* key_value, uint8_t key_size) {
  if (input_size + TC_AES_BLOCK_SIZE > output_size || key_size < NDN_SEC_AES_MIN_KEY_SIZE) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  struct tc_aes_key_sched_struct schedule;
  tc_aes128_set_encrypt_key(&schedule, key_value);
  if (tc_cbc_mode_encrypt(output_value, input_size + TC_AES_BLOCK_SIZE,
                          input_value, input_size, aes_iv, &schedule) == 0) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return 0;
}

int ndn_lite_aes_cbc_decrypt_tinycript(const uint8_t* input_value, uint8_t input_size,
                                       uint8_t* output_value, uint8_t output_size,
                                       const uint8_t* aes_iv,
                                       const uint8_t* key_value, uint8_t key_size) {
  if (output_size < input_size - TC_AES_BLOCK_SIZE || key_size < NDN_SEC_AES_MIN_KEY_SIZE) {
    return NDN_SEC_WRONG_AES_SIZE;
  }
  (void)aes_iv;
  struct tc_aes_key_sched_struct schedule;
  tc_aes128_set_decrypt_key(&schedule, key_value);
  if (tc_cbc_mode_decrypt(output_value, input_size - TC_AES_BLOCK_SIZE,
                          input_value + TC_AES_BLOCK_SIZE, input_size - TC_AES_BLOCK_SIZE,
                          input_value, &schedule) == 0) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  return 0;
}