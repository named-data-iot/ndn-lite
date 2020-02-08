/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_SECURITY_HMAC_H_
#define NDN_SECURITY_HMAC_H_

#include "../ndn-error-code.h"
#include "ndn-lite-sec-config.h"
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The opaque abstract hmac key struct to be implemented by the backend.
 */
typedef struct abstract_hmac_key abstract_hmac_key_t;
typedef struct abstract_hmac_sha256_state abstract_hmac_sha256_state_t;

/**
 * The APIs that are supposed to be implemented by the backend.
 */
typedef uint32_t (*ndn_hmac_get_key_size_impl)(const abstract_hmac_key_t* hmac_key);
typedef const uint8_t* (*ndn_hmac_get_key_value_impl)(const abstract_hmac_key_t* hmac_key);
typedef int (*ndn_hmac_load_key_impl)(abstract_hmac_key_t* hmac_key,
                                      const uint8_t* key_value, uint32_t key_size);

typedef int (*ndn_hmac_sha256_init_impl)(abstract_hmac_sha256_state_t* state, const abstract_hmac_key_t* hmac_key);
typedef int (*ndn_hmac_sha256_update_impl)(abstract_hmac_sha256_state_t* state, const uint8_t* data, uint32_t datalen);
typedef int (*ndn_hmac_sha256_final_impl)(abstract_hmac_sha256_state_t* state, uint8_t* hmac_result);
typedef int (*ndn_hmacprng_impl)(const uint8_t* input_value, uint32_t input_size,
                                 uint8_t* output_value, uint32_t output_size,
                                 const uint8_t* seed_value, uint32_t seed_size,
                                 const uint8_t* additional_value, uint32_t additional_size);

/**
 * The structure to represent the backend implementation.
 */
typedef struct ndn_hmac_backend {
  ndn_hmac_get_key_size_impl get_key_size;
  ndn_hmac_get_key_value_impl get_key_value;
  ndn_hmac_load_key_impl load_key;
  ndn_hmac_sha256_init_impl hmac_sha256_init;
  ndn_hmac_sha256_update_impl hmac_sha256_update;
  ndn_hmac_sha256_final_impl hmac_sha256_final;
  ndn_hmacprng_impl hmacprng;
} ndn_hmac_backend_t;

/**
 * The structure to keep a HMAC key.
 */
typedef struct ndn_hmac_key {
  abstract_hmac_key_t abs_key;
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
} ndn_hmac_key_t;

typedef struct ndn_hmac_sha256_state {
  abstract_hmac_sha256_state_t abs_state;
} ndn_hmac_sha256_state_t;

ndn_hmac_backend_t*
ndn_hmac_get_backend(void);

/**
 * Get hmac key size in unit of byte.
 * @param hmac_key. Input. NDN hmac key.
 */
uint32_t
ndn_hmac_get_key_size(const ndn_hmac_key_t* hmac_key);

/**
 * Get hmac key bytes.
 * @param hmac_key. Input. NDN hmac key.
 */
const uint8_t*
ndn_hmac_get_key_value(const ndn_hmac_key_t* hmac_key);

/**
 * Load in-memory key bits into an NDN hmac key.
 * @param hmac_key. Output. NDN hmac key.
 * @param key_value. Input. Key bytes.
 * @param key_size. Input. The size of the key bytes.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_hmac_load_key(ndn_hmac_key_t* hmac_key,
                  const uint8_t* key_value, uint32_t key_size);

/**
 * Initialize a HMAC key.
 * @param hmac_key. Input. The HMAC key whose info will be set.
 * @param key_value. Input. The key value bytes to set.
 * @param key_size. Input. The key size. Should not larger than 32 bytes.
 * @param key_id. Input. The key id to be set with this key.
 * @return NDN_SUCCESS(0) if there is no error.
 */
static inline int
ndn_hmac_key_init(ndn_hmac_key_t* hmac_key, const uint8_t* key_value,
                  uint32_t key_size, uint32_t key_id)
{
  ndn_hmac_load_key(hmac_key, key_value, key_size);
  hmac_key->key_id = key_id;
  return NDN_SUCCESS;
}

/**
 * Generate HMAC using sha256 digest algorithm.
 * @note This function will invoke different impl depending on the backend.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_hmac_sha256_init(ndn_hmac_sha256_state_t* state, const ndn_hmac_key_t* hmac_key);

int
ndn_hmac_sha256_update(ndn_hmac_sha256_state_t* state, const void* payload, uint32_t payload_length);

int
ndn_hmac_sha256_final(ndn_hmac_sha256_state_t* state, uint8_t* hmac_result);

int
ndn_hmac_sha256(const void* payload, uint32_t payload_length,
                const ndn_hmac_key_t* hmac_key,
                uint8_t* hmac_result);

/**
 * Sign a buffer using HMAC algorithm.
 * The memory buffer to hold the signature should not be smaller than 32 bytes.
 * @param input_value. Input. Buffer prepared to sign.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Signature value.
 * @param output_max_size. Input. Buffer size of output_value
 * @param key_value. Input. HMAC key.
 * @param key_size. Input. Size of HMAC key.
 * @param output_used_size. Output. Size of used output buffer when signing complete.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_hmac_sign(const uint8_t* input_value, uint32_t input_size,
              uint8_t* output_value, uint32_t output_max_size,
              const ndn_hmac_key_t* hmac_key,
              uint32_t* output_used_size);

/**
 * Verify a HMAC signature.
 * @param input_value. Input. HMAC-signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. HMAC signature value.
 * @param sig_size. Input. HMAC signature size. Should be 32 bytes.
 * @param key_value. Input. HMAC key buffer.
 * @param key_size. Input. size of HMAC key.
 * @return NDN_SUCCESS (0) if verification succeeded.
 */
int
ndn_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                const uint8_t* sig_value, uint32_t sig_size,
                const ndn_hmac_key_t* hmac_key);

/**
 * Generate a HMAC key with specific key size and key id.
 * This function requires proper entropy source.
 * @note This function will invoke different imple depending on the backend.
 * @param input_value. Input. Personalization string.
 * @param input_size. Input. Personalization length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 * @param seed_value. Input. Entropy to mix into the prng.
 * @param seed_size. Input. Entropy length in bytes.
 * @param additional_value. Input. Additional input to the prng.
 * @param additional_size. Input. Additional input length in bytes.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_hmac_make_key(ndn_hmac_key_t* key, uint32_t key_id,
                  const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* personalization, uint32_t personalization_size,
                  const uint8_t* seed_value, uint32_t seed_size,
                  const uint8_t* additional_value, uint32_t additional_size,
                  uint32_t salt_size);

/**
 * Use HMAC-KDF (key derivation function) to generate a secure HMAC key.
 * This function requires proper entropy source.
 * @param input_value. Input. Random input that requires KDF.
 * @param input_size. Input. Random input length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 *   Important! in ndn-lite, the max allowed output size is NDN_SEC_HMAC_MAX_OUTPUT_SIZE
 * @param seed_value. Input. Entropy to mix into the prng.
 * @param seed_size. Input. Entropy length in bytes.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_hkdf(const uint8_t* input_value, uint32_t input_size,
         uint8_t* output_value, uint32_t output_size,
         const uint8_t* seed_value, uint32_t seed_size,
         const uint8_t* info_value, uint32_t info_size);

/**
 * Use HMAC-PRNG algorithm to generate pseudo-random bytes.
 * This function requires proper entropy source.
 * @param input_value. Input. Personalization string.
 * @param input_size. Input. Personalization length in bytes.
 * @param output_value. Output. Buffer to receive output.
 * @param output_size. Input. Size of the output buffer.
 * @param seed_value. Input. Entropy to mix into the prng, highly recommend larger than 32 bytes.
 * @param seed_size. Input. Entropy length in bytes, highly recommend larger than 32 bytes.
 * @param additional_value. Input. Additional input to the prng
 * @param additional_size. Input. Additional input length in bytes
 * @return NDN_SUCCESS(0) if there is no error.
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
