/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_SIGN_VERIFY_H_
#define NDN_SECURITY_SIGN_VERIFY_H_

#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Use SHA-256 Algorithm to sign buffer. Memory buffer to hold the siganture should not smaller than 32 bytes.
 * @param input_value. Input. Buffer prepared to sign.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Signature value.
 * @param output_max_size. Input. Buffer size of output_value
 * @param output_used_size. Output. Size of used output buffer when signing complete. 
 * @return 0 if there is no error.
 */
int
ndn_signer_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                       uint8_t* output_value, uint32_t output_max_size,
                       uint32_t* output_used_size);

/**
 * Use ECDSA Algorithm to sign buffer. This function will automatically use 
 * deterministic signing when no hardware pseudo-random number generater available.
 * @param input_value. Input. Buffer prepared to sign.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Signature value.
 * @param output_max_size. Input. Buffer size of output_value
 * @param prv_key_value. Input. ECDSA private key buffer.
 * @param prv_key_size. Input. Size of private key.
 * @param ecdsa_type. Input. Type of ECDSA siganture. Can be secp160r1, secp192r1, secp224r1, 
 *        secp256r1, secp256k1.
 * @param output_used_size. Output. Size of used output buffer when signing complete. 
 * @return 0 if there is no error.
 */
int
ndn_signer_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value, uint32_t output_max_size,
                      const uint8_t* prv_key_value, uint32_t prv_key_size,
                      uint8_t ecdsa_type, uint32_t* output_used_size);

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
ndn_signer_hmac_sign(const uint8_t* input_value, uint32_t input_size,
                     uint8_t* output_value, uint32_t output_max_size,
                     const uint8_t* key_value, uint32_t key_size,
                     uint32_t* output_used_size);

/**
 * Use SHA-256 Algorithm to verify signature. Memory buffer to hold the siganture should not smaller than 32 bytes.
 * @param input_value. Input. SHA-256 Signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. SHA-256 signature value.
 * @param sig_size. Input. SHA-256 signature size.
 * @return 0 if verification succeeded.
 */
int
ndn_verifier_sha256_verify(const uint8_t* input_value, uint32_t input_size,
                           const uint8_t* sig_value, uint32_t sig_size);

/**
 * Use ECDSA Algorithm to verify signature. Memory buffer to hold the siganture should not larger than 64 bytes.
 * @param input_value. Input. ECDSA Signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. ECDSA signature value.
 * @param sig_size. Input. ECDSA signature size. Should not larger than 64 bytes.
 * @param pub_key_value. Input. ECDSA public key.
 * @param pub_key_size. Input. size of public key. Should not larger than 64 bytes.
 * @return 0 if verification succeeded.
 */
int
ndn_verifier_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                          const uint8_t* sig_value, uint32_t sig_size,
                          const uint8_t* pub_key_value,
                          uint32_t pub_key_size, uint8_t ecdsa_type);

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
ndn_verifier_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                         const uint8_t* sig_value, uint32_t sig_size,
                         const uint8_t* key_value, uint32_t key_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_SIGN_VERIFY_H_
