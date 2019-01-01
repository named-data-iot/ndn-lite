/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "../ndn-lite-sec-config.h"

#ifdef NDN_LITE_SEC_BACKEND_SIGN_VERIFY_DEFAULT

#include "../ndn-lite-sign-verify.h"
#include "../detail/detail-hmac/ndn-lite-hmac-tinycrypt-impl.h"
#include "../detail/detail-sha256/ndn-lite-sha256-tinycrypt-impl.h"
#include "../detail/detail-ecc/ndn-lite-ecc-microecc-impl.h"
#include "../detail/sec-lib/tinycrypt/tc_hmac.h"
#include "../detail/sec-lib/micro-ecc/uECC.h"

static int
sha256(const uint8_t* data, size_t datalen, uint8_t* hash_result)
{
  return ndn_lite_sha256_tinycrypt(data, datalen, hash_result);
}

static int
hmac_sha256(const uint8_t* key, unsigned int key_size,
            const void* data, unsigned int data_length,
            uint8_t* hmac_result)
{
  return ndn_lite_hmac_sha256_tinycrypt(key, key_size,
                                        data, data_length,
                                        hmac_result);
}

int
ndn_signer_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                       uint8_t* output_value, uint32_t output_max_size,
                       uint32_t* output_used_size)
{
  if (output_max_size < NDN_SEC_SHA256_HASH_SIZE)
    return NDN_OVERSIZE;
  if (sha256(input_value, input_size, output_value) != NDN_SUCCESS) {
    return NDN_SEC_SHA256_HASH_SIZE;
  }
  *output_used_size = NDN_SEC_SHA256_HASH_SIZE;
  return 0;
}

int
ndn_signer_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value, uint32_t output_max_size,
                      const uint8_t* prv_key_value, uint32_t prv_key_size,
                      uint8_t ecdsa_type, uint32_t* output_used_size)
{
  return ndn_lite_ecdsa_sign_microecc(input_value, input_size,
                                      output_value, output_max_size,
                                      prv_key_value, prv_key_size,
                                      ecdsa_type, output_used_size);
}

int
ndn_signer_hmac_sign(const uint8_t* input_value, uint32_t input_size,
                     uint8_t* output_value, uint32_t output_max_size,
                     const uint8_t* key_value, uint32_t key_size,
                     uint32_t* output_used_size)
{
  if (output_max_size < 32)
    return NDN_OVERSIZE;
  int ret_val = hmac_sha256(key_value, key_size, input_value, input_size, output_value);
  if (ret_val != NDN_SUCCESS) {
    return ret_val;
  }
  *output_used_size = 32;
  return 0;
}

int
ndn_verifier_sha256_verify(const uint8_t* input_value, uint32_t input_size,
                           const uint8_t* sig_value, uint32_t sig_size)
{
  
}

int
ndn_verifier_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                          const uint8_t* sig_value, uint32_t sig_size,
                          const uint8_t* pub_key_value,
                          uint32_t pub_key_size, uint8_t ecdsa_type)
{
  return ndn_lite_ecdsa_verify_microecc(input_value, input_size,
                                        sig_value, sig_size,
                                        pub_key_value,
                                        pub_key_size, ecdsa_type);
}

int
ndn_verifier_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                         const uint8_t* sig_value, uint32_t sig_size,
                         const uint8_t* key_value, uint32_t key_size)
{
  if (sig_size != 32)
    return NDN_SEC_WRONG_SIG_SIZE;

  uint8_t input_hmac[32] = {0};
  hmac_sha256(key_value, key_size, input_value, input_size, input_hmac);
  if (memcmp(input_hmac, sig_value, sizeof(input_hmac)) != 0)
    return -1;
  else
    return 0;
}

#endif // NDN_LITE_SEC_BACKEND_SIGN_VERIFY_DEFAULT
