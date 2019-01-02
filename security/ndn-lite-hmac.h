/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_HMAC_H_
#define NDN_SECURITY_HMAC_H_

#include "../ndn-error-code.h"
#include "ndn-lite-crypto-key.h"
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

int
hmac_sha256(const void* payload, uint32_t payload_length,
            const uint8_t* key, uint32_t key_size,
            uint8_t* hmac_result);

/**
 * Use HMAC Algorithm to sign buffer. Memory buffer to hold the siganture should not smaller than 32 bytes.
 * @param input_value. Input. Buffer prepared to sign.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Signature value.
 * @param output_max_size. Input. Buffer size of output_value
 * @param key_value. Input. HMAC key.
 * @param key_size. Input. Size of HMAC key.
 * @param output_used_size. Output. Size of used output buffer when signing complete.
 * @return 0 if there is no error.
 */
int
ndn_hmac_sign(const uint8_t* input_value, uint32_t input_size,
              uint8_t* output_value, uint32_t output_max_size,
              const uint8_t* key_value, uint32_t key_size,
              uint32_t* output_used_size);

/**
 * Use HMAC Algorithm to verify signature. Memory buffer to hold the siganture should not larger than 32 bytes.
 * @param input_value. Input. HMAC Signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. HMAC signature value.
 * @param sig_size. Input. HMAC signature size. Should be 32 bytes.
 * @param key_value. Input. HMAC key buffer.
 * @param key_size. Input. size of HMAC key.
 * @return 0 if verification succeeded.
 */
int
ndn_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                const uint8_t* sig_value, uint32_t sig_size,
                const uint8_t* key_value, uint32_t key_size);

/**
 * Make a HMAC key with specific key size and key id.
 * This function requires proper entropy source.
 * @param input_value. Input. Personalization string.
 * @param input_size. Input. Personalization length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 * @param seed_value. Input. Entropy to mix into the prng.
 * @param seed_size. Input. Entropy length in bytes.
 * @param additional_value. Input. Additional input to the prng.
 * @param additional_size. Input. Additional input length in bytes.
 * @return 0 if there is no error.
 */
int
ndn_hmac_make_key(ndn_hmac_key_t* key, uint32_t key_id,
                  const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* personalization, uint32_t personalization_size,
                  const uint8_t* seed_value, uint32_t seed_size,
                  const uint8_t* additional_value, uint32_t additional_size,
                  uint32_t salt_size);

/**
 * Use HMAC-KDF Algorithm to generate a secure HMAC key.
 * This function requires proper entropy source.
 * @param input_value. Input. Random input that requires KDF.
 * @param input_size. Input. Random input length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 * @param seed_value. Input. Entropy to mix into the prng.
 * @param seed_size. Input. Entropy length in bytes.
 * @return 0 if there is no error.
 */
int
ndn_hkdf(const uint8_t* input_value, uint32_t input_size,
         uint8_t* output_value, uint32_t output_size,
         const uint8_t* seed_value, uint32_t seed_size);

/**
 * Use HMAC-PRNG Algorithm to generate pseudo-random bytes.
 * This function requires proper entropy source.
 * @param input_value. Input. Personalization string.
 * @param input_size. Input. Personalization length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 * @param seed_value. Input. Entropy to mix into the prng, highly recommend larger than 32 bytes.
 * @param seed_size. Input. Entropy length in bytes, highly recommend larger than 32 bytes.
 * @param additional_value. Input. Additional input to the prng
 * @param additional_size. Input. Additional input length in bytes
 * @return 0 if there is no error.
 */
int
ndn_hmacprng(const uint8_t* input_value, uint32_t input_size,
             uint8_t* output_value, uint32_t output_size,
             const uint8_t* seed_value, uint32_t seed_size,
             const uint8_t* additional_value, uint32_t additional_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_HMAC_H_
