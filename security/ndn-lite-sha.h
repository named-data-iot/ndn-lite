/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_SECURITY_SHA_H_
#define NDN_SECURITY_SHA_H_

#include "ndn-lite-sec-config.h"
#include "../ndn-error-code.h"
#include "../ndn-constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The opaque abstract SHA256 state struct to be implemented by the backend.
 */
typedef struct abstract_sha256_state abstract_sha256_state_t;

/**
 * The APIs that are supposed to be implemented by the backend.
 */
typedef int (*ndn_sha256_init_impl)(abstract_sha256_state_t* state);
typedef int (*ndn_sha256_update_impl)(abstract_sha256_state_t* state, const uint8_t* data, uint32_t datalen);
typedef int (*ndn_sha256_finish_impl)(abstract_sha256_state_t* state, uint8_t* hash_result);

/**
 * The structure to represent the backend implementation.
 */
typedef struct ndn_sha_backend {
  ndn_sha256_init_impl sha256_init;
  ndn_sha256_update_impl sha256_update;
  ndn_sha256_finish_impl sha256_finish;
} ndn_sha_backend_t;


/**
 * The structure to represent the SHA256 hash state.
 */
typedef struct ndn_sha256_state {
  abstract_sha256_state_t abs_state;

} ndn_sha256_state_t;

ndn_sha_backend_t*
ndn_sha_get_backend(void);


/**
 *  SHA256 initialization procedure.
 *  @param state. Input. SHA256 state struct.
 *  @return NDN_SUCCESS (0) if there if no error.
 */
int
ndn_sha256_init(ndn_sha256_state_t* state);

/*
 *  SHA256 update procedure. Hashes datalen bytes addressed by data into state
 *  @note Assumes state has been initialized
 *  @param state. Input. SHA256 state struct.
 *  @param data. Input. message to hash.
 *  @param datalen. Input. length of message to hash.
 *  @return NDN_SUCCESS (0) if there is no error.
 */
int
ndn_sha256_update(ndn_sha256_state_t* state, const uint8_t* data, uint32_t datalen);

/**
 *  SHA256 final procedure. Inserts the completed hash computation into digest.
 *  @param hash_result. Output. digest in unsigned eight bit integer.
 *  @param state. Input. SHA256 state struct.
 *  @return NDN_SUCCESS (0) if there is no error.
 */
int
ndn_sha256_finish(ndn_sha256_state_t* state, uint8_t* hash_result);

/**
 *  SHA256 a series of bytes into the result
 *  @param data. Input. The input data buffer.
 *  @param datalen. Input. The length of the input data.
 *  @param hash_result. Output. Output buffer whose length should be at least 32.
 *  @return NDN_SUCCESS (0) if there is no error.
 */
int
ndn_sha256(const uint8_t* data, uint32_t datalen, uint8_t* hash_result);

/**
 * Sign a buffer using SHA-256 algorithm.
 * The memory buffer to hold the signature should not be smaller than 32 bytes.
 * @param input_value. Input. Buffer prepared to sign.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Signature value.
 * @param output_max_size. Input. Buffer size of output_value
 * @param output_used_size. Output. Size of used output buffer when signing complete.
 * @return NDN_SUCCESS if there is no error.
 */
int
ndn_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_max_size,
                uint32_t* output_used_size);

/**
 * Verify a SHA-256 signature.
 * @param input_value. Input. SHA-256-signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. SHA-256 signature value.
 * @param sig_size. Input. SHA-256 signature size. Should be 32 bytes.
 * @return NDN_SUCCESS if verification succeeded.
 */
int
ndn_sha256_verify(const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* sig_value, uint32_t sig_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_AES_H_
