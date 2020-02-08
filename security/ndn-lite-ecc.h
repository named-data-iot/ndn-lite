/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_SECURITY_ECC_H_
#define NDN_SECURITY_ECC_H_

#include "../ndn-error-code.h"
#include "ndn-lite-sec-config.h"
#include "ndn-lite-rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The opaque abstract ecc key struct to be implemented by the backend.
 */
typedef struct abstract_ecc_pub_key abstract_ecc_pub_key_t;
typedef struct abstract_ecc_prv_key abstract_ecc_prv_key_t;

/**
 * The APIs that are supposed to be implemented by the backend.
 */
typedef uint32_t (*ndn_ecc_get_pub_key_size_impl)(const abstract_ecc_pub_key_t* pub_key);
typedef uint32_t (*ndn_ecc_get_prv_key_size_impl)(const abstract_ecc_prv_key_t* prv_key);
typedef const uint8_t* (*ndn_ecc_get_pub_key_value_impl)(const abstract_ecc_pub_key_t* pub_key);
typedef int (*ndn_ecc_load_pub_key_impl)(abstract_ecc_pub_key_t* pub_key,
                                         const uint8_t* key_value, uint32_t key_size);
typedef int (*ndn_ecc_load_prv_key_impl)(abstract_ecc_prv_key_t* prv_key,
                                         const uint8_t* key_value, uint32_t key_size);
typedef int (*ndn_ecc_set_rng_impl)(ndn_rng_impl rng);
typedef int (*ndn_ecdsa_sign_impl)(const uint8_t* payload_value, uint32_t payload_size,
                                   uint8_t* output_value, uint32_t output_max_size,
                                   const abstract_ecc_prv_key_t* prv_key,
                                   uint8_t ecdsa_type, uint32_t* output_used_size);
typedef int (*ndn_ecdsa_verify_impl)(const uint8_t* payload_value, uint32_t payload_size,
                                     const uint8_t* sig_value, uint32_t sig_size,
                                     const abstract_ecc_pub_key_t* pub_key, uint8_t ecdsa_type);
typedef int (*ndn_ecc_make_key_impl)(abstract_ecc_pub_key_t* pub_key,
                                     abstract_ecc_prv_key_t* prv_key,
                                     uint8_t curve_type);
typedef int (*ndn_ecc_dh_shared_secret_impl)(const abstract_ecc_pub_key_t* ecc_pub,
                                             const abstract_ecc_prv_key_t* ecc_prv,
                                             uint8_t curve_type, uint8_t* output,
                                             uint32_t output_size);

/**
 * The structure to represent the backend implementation.
 */
typedef struct ndn_ecc_backend {
  ndn_ecc_get_pub_key_size_impl get_pub_key_size;
  ndn_ecc_get_prv_key_size_impl get_prv_key_size;
  ndn_ecc_get_pub_key_value_impl get_pub_key_value;
  ndn_ecc_load_pub_key_impl load_pub_key;
  ndn_ecc_load_prv_key_impl load_prv_key;
  ndn_ecc_set_rng_impl set_rng;
  ndn_ecc_make_key_impl make_key;
  ndn_ecc_dh_shared_secret_impl dh_shared_secret;
  ndn_ecdsa_sign_impl ecdsa_sign;
  ndn_ecdsa_verify_impl ecdsa_verify;
} ndn_ecc_backend_t;

/**
 * The structure to keep an ECC public key.
 */
typedef struct ndn_ecc_pub {
  abstract_ecc_pub_key_t abs_key;
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
  /**
   * The curve type of current key. Can be secp160r1, secp192r1, secp224r1, secp256r1, secp256k1.
   */
  uint8_t curve_type;
} ndn_ecc_pub_t;

/**
 * The structure to keep an ECC private key.
 */
typedef struct ndn_ecc_prv {
  abstract_ecc_prv_key_t abs_key;
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
  /**
   * The curve type of current key. Can be secp160r1, secp192r1, secp224r1, secp256r1, secp256k1.
   */
  uint8_t curve_type;
} ndn_ecc_prv_t;

ndn_ecc_backend_t*
ndn_ecc_get_backend(void);

/**
 * Get public key size in unit of byte.
 * @param pub_key. Input. NDN ECC public key.
 */
uint32_t
ndn_ecc_get_pub_key_size(const ndn_ecc_pub_t* pub_key);

/**
 * Get private key size in unit of byte.
 * @param prv_key. Input. NDN ECC private key.
 */
uint32_t
ndn_ecc_get_prv_key_size(const ndn_ecc_prv_t* prv_key);

/**
 * Get public key bytes.
 * @param pub_key. Input. NDN ECC public key.
 */
const uint8_t*
ndn_ecc_get_pub_key_value(const ndn_ecc_pub_t* pub_key);

/**
 * Load in-memory key bits into an NDN public key.
 * @param pub_key. Output. NDN ECC public key.
 * @param key_value. Input. Key bytes.
 * @param key_size. Input. The size of the key bytes.
 * @return NDN_SUCCESS(0) if there is no error.
 */
// int
// ndn_ecc_load_pub_key(ndn_ecc_pub_t* pub_key, uint8_t curve_type, uint32_t key_id,
//                      const uint8_t* key_value, uint32_t key_size);

/**
 * Initialize an ECC public key.
 * @param ecc_pub. Input. The ECC public key whose info will be set.
 * @param key_value. Input. The key value bytes to set.
 * @param key_size. Input. The key size. Should not larger than 64 bytes.
 * @param curve_type. Input. Type of ECC Curve. Can be secp160r1, secp192r1, secp224r1,
 *        secp256r1, secp256k1.
 * @param key_id. Input. The key id to be set with this ECC public key.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_ecc_pub_init(ndn_ecc_pub_t* ecc_pub, const uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id);

/**
 * Load in-memory key bits into an NDN private key.
 * @param prv_key. Output. NDN ECC private key.
 * @param key_value. Input. Key bytes.
 * @param key_size. Input. The size of the key bytes.
 * @return NDN_SUCCESS(0) if there is no error.
 */
// int
// ndn_ecc_load_prv_key(ndn_ecc_prv_t* prv_key, uint8_t curve_type, uint32_t key_id,
//                      const uint8_t* key_value, uint32_t key_size);

/**
 * Initialize an ECC private key.
 * @param ecc_prv. Input. The ECC private key whose info will be set.
 * @param key_value. Input. The key value bytes to set.
 * @param key_size. Input. The key size. Should not larger than 32 bytes.
 * @param curve_type. Input. Type of ECC Curve. Can be secp160r1, secp192r1, secp224r1,
 *        secp256r1, secp256k1.
 * @param key_id. Input. The key id to be set with this ECC private key.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_ecc_prv_init(ndn_ecc_prv_t* ecc_prv, const uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id);

/**
 * Set RNG function for backend implementation library,
 * which need this to perform non-deterministic signing.
 * This function should be called before ndn_ecdsa_sign() and ndn_ecc_make_key().
 * IMPROTANT: the rng should return 1 if running successfully
 * @param rng. Input. RNG function which will be bound to the backend implementation library.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_ecc_set_rng(ndn_rng_impl rng);

/**
 * Generate an ECC key pair with specific curve type and key id.
 * @param ecc_pub. Output. ECC public key whose key bytes to be generated.
 * @param ecc_prv. Output. ECC private key whose key bytes to be generated.
 * @param curve_type. Input. The chosen ECC curve type to generate the key pair.
 * @param key_id. Input. The key id to be set with public and private key.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_ecc_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                 uint8_t curve_type, uint32_t key_id);

/**
 * Negotiate a shared secret wih given ECC public and private keys via ECDH.
 * @param ecc_pub. Input. Input ECC public key.
 * @param ecc_prv. Input. Input ECC private key.
 * @param output. Output. Buffer to receive negotiated shared secret.
 * @param output_size. Input. Size of the output buffer. Should not be smaller than 24 bytes.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_ecc_dh_shared_secret(const ndn_ecc_pub_t* ecc_pub, const ndn_ecc_prv_t* ecc_prv, uint8_t* output, uint32_t output_size);

/**
 * Sign a buffer using ECDSA algorithm. This function will automatically use
 * deterministic signing when no hardware pseudo-random number generator is available.
 * The signature generated will be in ASN.1 DER format.
 * @param input_value. Input. Buffer prepared to sign.
 * @param input_size. Input. Size of input buffer.
 * @param output_value. Output. Signature value.
 * @param output_max_size. Input. Buffer size of output_value
 * @param prv_key_value. Input. ECDSA private key buffer.
 * @param prv_key_size. Input. Size of private key.
 * @param output_used_size. Output. Size of used output buffer when signing complete.
 * @return NDN_SUCCESS(0) if there is no error.
 */
int
ndn_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
               uint8_t* output_value, uint32_t output_max_size,
               const ndn_ecc_prv_t* ecc_prv_key, uint32_t* output_used_size);

/**
 * Verify an ECDSA signature in ASN.1 DER format.
 * @param input_value. Input. ECDSA-signed buffer.
 * @param input_size. Input. Size of input buffer.
 * @param sig_value. Input. ECDSA signature value.
 * @param sig_size. Input. ECDSA signature size. Should not be larger than 64 bytes.
 * @param ecc_pub_key. Input. ECDSA public key.
 * @return NDN_SUCCESS(0) if verification succeeded.
 */
int
ndn_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                 const uint8_t* sig_value, uint32_t sig_size,
                 const ndn_ecc_pub_t* ecc_pub_key);


#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_ECC_H_
