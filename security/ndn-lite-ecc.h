/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_ECC_H_
#define NDN_SECURITY_ECC_H_

#include "../ndn-error-code.h"
#include "ndn-lite-crypto-key.h"
#include "ndn-lite-rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set RNG function for backend implementation library,
 * which need this to perform non-deterministic signing.
 * This function should be called before ndn_ecdsa_sign() and ndn_ecc_make_key().
 * @param rng. Input. RNG function which will be bound to the backend implementation library.
 */
void
ndn_ecc_set_rng(ndn_ECC_RNG_Function rng);

/**
 * Sign a buffer using ECDSA algorithm. This function will automatically use
 * deterministic signing when no hardware pseudo-random number generator is available.
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
ndn_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
               uint8_t* output_value, uint32_t output_max_size,
               const uint8_t* prv_key_value, uint32_t prv_key_size,
               uint8_t ecdsa_type, uint32_t* output_used_size);

/**
 * Verify an ECDSA signature.
 * @param input_value. Input. ECDSA-signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. ECDSA signature value.
 * @param sig_size. Input. ECDSA signature size. Should not be larger than 64 bytes.
 * @param pub_key_value. Input. ECDSA public key.
 * @param pub_key_size. Input. size of public key. Should not be larger than 64 bytes.
 * @return 0 if verification succeeded.
 */
int
ndn_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                 const uint8_t* sig_value, uint32_t sig_size,
                 const uint8_t* pub_key_value,
                 uint32_t pub_key_size, uint8_t ecdsa_type);

/**
 * Generate an ECC key pair with specific curve type and key id.
 * @note Current backend implementation (i.e., tinycrypt) only supports curve type secp256r1.
 * @param ecc_pub. Output. ECC public key whose key bytes to be generated.
 * @param ecc_prv. Output. ECC private key whose key bytes to be generated.
 * @param curve_type. Input. The chosen ECC curve type to generate the key pair.
 * @param key_id. Input. The key id to be set with public and private key.
 * @return 0 if there is no error.
 */
int
ndn_ecc_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                 uint8_t curve_type, uint32_t key_id);

/**
 * Negotiate a shared secret wih given ECC public and private keys via ECDH.
 * @note Current backend implementation (i.e., tinycrypt) only supports curve type secp256r1.
 * @param ecc_pub. Input. Input ECC public key.
 * @param ecc_prv. Input. Input ECC private key.
 * @param curve_type. Input. ECC curve type. Should be the same type of input public and private key.
 * @param output. Output. Buffer to receive negotiated shared secret.
 * @param output_size. Input. Size of the output buffer. Should not be smaller than 24 bytes.
 * @return 0 if there is no error.
 */
int
ndn_ecc_dh_shared_secret(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                         uint8_t curve_type, uint8_t* output, uint32_t output_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_ECC_H_
