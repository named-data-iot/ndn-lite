/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_SECURITY_CRYPTO_KEY_H
#define NDN_SECURITY_CRYPTO_KEY_H

#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ndn_ECC_RNG_Function type
 *
 * This type is the same as micro-ecc/uECC.h::uECC_RNG_Function
 *
 * The RNG function should fill 'size' random bytes into 'dest'.
 * It should return 1 if 'dest' was filled with random data,
 * or 0 if the random data could not be generated.
 * The filled-in values should be either truly random, or from a cryptographically-secure PRNG.
 * Setting a correctly functioning RNG function improves the resistance to side-channel attacks.
 **/
typedef int (*ndn_ECC_RNG_Function)(uint8_t *dest, unsigned size);

/**
 * The structure to keep an ECC public key.
 */
typedef struct ndn_ecc_pub {
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[64];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
  /**
   * The curve type of current key. Can be secp160r1, secp192r1, secp224r1, secp256r1, secp256k1.
   */
  uint8_t curve_type;
} ndn_ecc_pub_t;

/**
 * The structure to keep an ECC private key.
 */
typedef struct ndn_ecc_prv {
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[32];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
  /**
   * The curve type of current key. Can be secp160r1, secp192r1, secp224r1, secp256r1, secp256k1.
   */
  uint8_t curve_type;
} ndn_ecc_prv_t;

/**
 * The structure to keep a HMAC key.
 */
typedef struct ndn_hmac_key {
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[32];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
} ndn_hmac_key_t;

/**
 * The structure to keep an AES-128 key.
 */
typedef struct ndn_aes_key {
  /**
   * The KEY ID of current key. Should be unique.
   */
  uint32_t key_id;
  /**
   * The key bytes buffer of current key.
   */
  uint8_t key_value[32];
  /**
   * The key size of key bytes.
   */
  uint32_t key_size;
} ndn_aes_key_t;

/**
 * Initialize an ECC public key.
 * @param ecc_pub. Input. The ECC public key whose info will be set.
 * @param key_value. Input. The key value bytes to set.
 * @param key_size. Input. The key size. Should not larger than 64 bytes.
 * @param curve_type. Input. Type of ECC Curve. Can be secp160r1, secp192r1, secp224r1,
 *        secp256r1, secp256k1.
 * @param key_id. Input. The key id to be set with this ECC public key.
 * @return 0 if there is no error.
 */
static inline int
ndn_ecc_pub_init(ndn_ecc_pub_t* ecc_pub, uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  if (key_size > 64)
    return NDN_SEC_WRONG_KEY_SIZE;
  memcpy(ecc_pub->key_value, key_value, key_size);
  ecc_pub->key_size = key_size;
  ecc_pub->curve_type = curve_type;
  ecc_pub->key_id = key_id;
  return 0;
}

/**
 * Initialize an ECC private key.
 * @param ecc_prv. Input. The ECC private key whose info will be set.
 * @param key_value. Input. The key value bytes to set.
 * @param key_size. Input. The key size. Should not larger than 32 bytes.
 * @param curve_type. Input. Type of ECC Curve. Can be secp160r1, secp192r1, secp224r1,
 *        secp256r1, secp256k1.
 * @param key_id. Input. The key id to be set with this ECC private key.
 * @return 0 if there is no error.
 */
static inline int
ndn_ecc_prv_init(ndn_ecc_prv_t* ecc_prv, uint8_t* key_value,
                 uint32_t key_size, uint8_t curve_type, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_SEC_WRONG_KEY_SIZE;
  memcpy(ecc_prv->key_value, key_value, key_size);
  ecc_prv->key_size = key_size;
  ecc_prv->curve_type = curve_type;
  ecc_prv->key_id = key_id;
  return 0;
}

/**
 * Initialize a HMAC key.
 * @param key. Input. The HMAC key whose info will be set.
 * @param key_value. Input. The key value bytes to set.
 * @param key_size. Input. The key size. Should not larger than 32 bytes.
 * @param key_id. Input. The key id to be set with this key.
 * @return 0 if there is no error.
 */
static inline int
ndn_hmac_key_init(ndn_hmac_key_t* key, uint8_t* key_value,
                  uint32_t key_size, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_SEC_WRONG_KEY_SIZE;
  key->key_size = key_size;
  memcpy(key->key_value, key_value, key_size);
  key->key_id = key_id;
  return 0;
}

/**
 * Initialize an AES-128 key.
 * @param key. Input. The HMAC key whose info will be set.
 * @param key_value. Input. The key value bytes to set.
 * @param key_size. Input. The key size. Should not larger than 32 bytes.
 * @param key_id. Input. The key id to be set with this key.
 * @return 0 if there is no error.
 */
static inline int
ndn_aes_key_init(ndn_aes_key_t* key, uint8_t* key_value,
                 uint32_t key_size, uint32_t key_id)
{
  if (key_size > 32)
    return NDN_SEC_WRONG_KEY_SIZE;
  key->key_size = key_size;
  memcpy(key->key_value, key_value, key_size);
  key->key_id = key_id;
  return 0;
}

/**
 * Set RNG function for backend implementation library, which need this to perform non-deterministic signing.
 * @param rng. Input. RNG function which will be bound to the backend implementation library.
 */
void
ndn_ecc_key_set_rng(ndn_ECC_RNG_Function rng);

/**
 * Make a ECC key pair with specific curve type and key id.
 * NOTES: Current backend implementation of (i.e., tinycrypt) only support curve type secp256r1.
 * @param ecc_pub. Output. ECC public key whose key bytes to be generated.
 * @param ecc_prv. Output. ECC private key whose key bytes to be generated.
 * @param curve_type. Input. The chosen ECC curve type to generate the key pair.
 * @param key_id. Input. The key id to be set with public and private key.
 * @return 0 if there is no error.
 */
int
ndn_ecc_key_make_key(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                      uint8_t curve_type, uint32_t key_id);

/**
 * Make a HMAC key with specific key size and key id.
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
 * Negotiate a shared secret wih given ECC public and private keys via ECDH.
 * @param ecc_pub. Input. Input ECC public key.
 * @param ecc_prv. Input. Input ECC private key.
 * @param curve_type. Input. ECC curve type. Should be the same type of input public and private key.
 * @param output. Output. Buffer to receive negotiated shared secret.
 * @param output_size. Input. Size of the output buffer. Should not smaller than 24 bytes.
 * @return 0 if there is no error.
 */
int
ndn_ecc_key_shared_secret(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                          uint8_t curve_type, uint8_t* output, uint32_t output_size);
#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_CRYPTO_KEY_H
