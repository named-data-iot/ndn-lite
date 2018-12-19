/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ecc-nrf-crypto-impl.h"

//#include "ecc-helpers.h"
//#include "sha256-helpers.h"
#include "../detail-sha256/sha256-nrf-crypto-impl.h"

#include "../../sign-on-basic-sec-consts.h"

#include <string.h>

int determineAsn1IntLength(const uint8_t *integer, uECC_Curve curve) {

  int priKeySize = uECC_curve_private_key_size(curve);

  // if the top bit of the first integer is 1, then an extra 0 byte needs to be added
  // to keep the integer positive since it is encoded in two's complement
  if ((integer[0] & 0x80) != 0x00) {
    return priKeySize + 1;
  }

  // if the top bit of the first integer is 0, then still need to check if there are more
  // zero bytes that can be cut off, since the ASN.1 encoding of a r and s ECDSA signature pair
  // requires that r and s be represented a minimal amount of bytes possible
  int len = priKeySize;
  for (int i = 0; i < priKeySize - 1; ++i) {
    if (((integer[i] << 8) | (integer[i + 1] & 0x80)) != 0x0000) {
      break;
    }
    --len;
  }
  return len;
}

uint8_t *
writeAsn1Int(uint8_t *output, const uint8_t *integer, int length, uECC_Curve curve) {
  *(output++) = ASN1_INTEGER;
  *(output++) = (uint8_t)(length);

  int priKeySize = uECC_curve_private_key_size(curve);

  if (length == priKeySize + 1) {
    *(output++) = 0x00;
    memmove(output, integer, priKeySize);
    return output + priKeySize;
  }

  memmove(output, integer + priKeySize - length, length);
  return output + length;
}

bool encodeSignatureBits(uint8_t *sig, uint16_t *sigLength, uECC_Curve curve) {
  const uint8_t *begin = sig;
  const uint8_t *r = sig + 8;
  const uint8_t *s = r + uECC_curve_private_key_size(curve);
  int rLength = determineAsn1IntLength(r, curve);
  int sLength = determineAsn1IntLength(s, curve);

  *(sig++) = ASN1_SEQUENCE;
  *(sig++) = 2 + rLength + 2 + sLength;
  sig = writeAsn1Int(sig, r, rLength, curve);
  sig = writeAsn1Int(sig, s, sLength, curve);

  *sigLength = sig - begin;

  return true;
}

int sign_on_basic_nrf_crypto_gen_ec_keypair(uint8_t *pub_key_buf, uint16_t pub_key_buf_len, uint16_t *pub_key_output_len,
    uint8_t *pri_key_buf, uint16_t pri_key_buf_len, uint16_t *pri_key_output_len,
    uECC_Curve curve) {

  // taken from "eddsa" example of SDK
  //**************************************//
  static nrf_crypto_ecc_key_pair_generate_context_t m_key_pair_generate_context;

  static uint8_t raw_priv_key[NRF_CRYPTO_ECC_SECP256R1_RAW_PRIVATE_KEY_SIZE];
  static uint8_t raw_pub_key[NRF_CRYPTO_ECC_SECP256K1_RAW_PUBLIC_KEY_SIZE];
  static uint8_t signature[NRF_CRYPTO_EDDSA_ED25519_SIGNATURE_SIZE];
  size_t signature_size = sizeof(signature);
  size_t raw_priv_key_size = sizeof(raw_priv_key);
  size_t raw_pub_key_size = sizeof(raw_pub_key);

  //**************************************//

  size_t pubKeySize = uECC_curve_private_key_size(curve);
  size_t priKeySize = uECC_curve_public_key_size(curve);

  if (pub_key_buf_len < pubKeySize)
    return SEC_OP_FAILURE;

  if (pri_key_buf_len < priKeySize)
    return SEC_OP_FAILURE;

  // taken from "eddsa" example of SDK
  //**************************************//

  // Generate key pair.
  nrf_crypto_ecc_private_key_t priv_key;
  nrf_crypto_ecc_public_key_t pub_key;
  ret_code_t err_code = nrf_crypto_ecc_key_pair_generate(&m_key_pair_generate_context,
      &g_nrf_crypto_ecc_secp256r1_curve_info,
      &priv_key,
      &pub_key);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  // Print public key.
  err_code = nrf_crypto_ecc_public_key_to_raw(&pub_key,
      raw_pub_key,
      &raw_pub_key_size);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  // Print private key.
  err_code = nrf_crypto_ecc_private_key_to_raw(&priv_key,
      raw_priv_key,
      &raw_priv_key_size);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  memcpy(pub_key_buf, raw_pub_key, raw_pub_key_size);
  *pub_key_output_len = (uint16_t) raw_pub_key_size;
  memcpy(pri_key_buf, raw_priv_key, raw_priv_key_size);
  *pri_key_output_len = (uint16_t) raw_priv_key_size;

  return SEC_OP_SUCCESS;

  //**************************************//
}

int sign_on_basic_nrf_crypto_gen_sha256_ecdsa_sig(const uint8_t *pri_key_raw, uECC_Curve curve,
                          const uint8_t *payload, uint16_t payload_len,
                          uint8_t *output_buf, uint16_t output_buf_len, uint16_t *output_len) {

  // taken from the "hash" example of the SDK
  //**************************************//
  nrf_crypto_hash_sha256_digest_t m_digest;
  const uint16_t m_digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;

  nrf_crypto_hash_context_t hash_context;

  //**************************************//

  if (output_buf_len < ECDSA_WITH_SHA256_SECP_256_ASN_ENCODED_SIGNATURE_SIZE)
    return SEC_OP_FAILURE;

  APP_LOG_HEX("Bytes of signature payload:", payload, payload_len);

  if (!sign_on_basic_nrf_crypto_gen_sha256_hash(payload, payload_len, m_digest))
    return SEC_OP_FAILURE;

  APP_LOG_HEX("Bytes of digest of signature payload:", m_digest, NRF_CRYPTO_HASH_SIZE_SHA256);
  
  uint16_t offsetForSignatureEncoding = 8;

  static nrf_crypto_ecc_private_key_t pri_key;
  ret_code_t err_code = NRF_SUCCESS;

  uint16_t pri_key_raw_len = uECC_curve_private_key_size(curve);

  APP_LOG("Bootstrapping request signature generation\n");

  // Alice converts her raw private key to internal representation
  err_code = nrf_crypto_ecc_private_key_from_raw(
      &g_nrf_crypto_ecc_secp256r1_curve_info,
      &pri_key,
      pri_key_raw,
      pri_key_raw_len);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  // Alice generates signature using ECDSA and SHA-256
  err_code = nrf_crypto_ecdsa_sign(
      NULL,
      &pri_key,
      m_digest,
      sizeof(m_digest),
      output_buf + offsetForSignatureEncoding,
      output_len);
  if (err_code != NRF_SUCCESS) {
    APP_LOG("inside of sign_on_basic_nrf_crypto_gen_sha256_ecdsa_sig, nrf_crypto_ecdsa_sign failed.\n");
    return SEC_OP_FAILURE;
  }

  // Key deallocation
  err_code = nrf_crypto_ecc_private_key_free(&pri_key);
  if (err_code != NRF_SUCCESS)
    return SEC_OP_FAILURE;

  if (!encodeSignatureBits(output_buf, output_len, uECC_secp256r1()))
    return SEC_OP_FAILURE;

  return SEC_OP_SUCCESS;
}

int sign_on_basic_nrf_crypto_gen_ecdh_shared_secret(
    const uint8_t *pub_key_raw, uint16_t pub_key_raw_len,
    const uint8_t *pri_key_raw, uint16_t pri_key_raw_len,
    uECC_Curve curve,
    uint8_t *output_buf, uint16_t output_buf_len, uint16_t *output_len) {

  if (output_buf_len < uECC_curve_public_key_size(curve)) {
    APP_LOG("Output buffer was too small to hold generated shared secret.\n");
    return false;
  }

  // taken from the "ecdh" example of the SDK
  //***************************************************//

  static nrf_crypto_ecdh_secp256r1_shared_secret_t diffie_hellman_shared_secret;

  //***************************************************//

  // taken from the "ecdh" example of the SDK
  //***************************************************//

  ret_code_t err_code = NRF_SUCCESS;

  APP_LOG("Generating shared secret.\n");

  static nrf_crypto_ecc_private_key_t pri_key;
  static nrf_crypto_ecc_public_key_t pub_key;
  static nrf_crypto_ecc_secp256r1_raw_public_key_t raw_key_buffer;
  err_code = NRF_SUCCESS;
  size_t size;

  // Alice receives Bob's raw public key
  size = pub_key_raw_len;
  memcpy(raw_key_buffer, pub_key_raw, pub_key_raw_len);

  APP_LOG_HEX("Value of N2 pub:", raw_key_buffer, size);

  // Alice converts Bob's raw public key to internal representation
  err_code = nrf_crypto_ecc_public_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
      &pub_key,
      raw_key_buffer, size);
  if (err_code != NRF_SUCCESS) {
    return SEC_OP_FAILURE;
  }

  // Alice converts her raw private key to internal representation
  err_code = nrf_crypto_ecc_private_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
      &pri_key,
      pri_key_raw,
      pri_key_raw_len);
  if (err_code != NRF_SUCCESS) {
    return SEC_OP_FAILURE;
  }

  // Alice computes shared secret using ECDH
  size = sizeof(diffie_hellman_shared_secret);
  err_code = nrf_crypto_ecdh_compute(NULL,
      &pri_key,
      &pub_key,
      diffie_hellman_shared_secret,
      &size);
  if (err_code != NRF_SUCCESS) {
    return SEC_OP_FAILURE;
  }

  *output_len = size;
  memcpy(output_buf, diffie_hellman_shared_secret, *output_len);

  APP_LOG_HEX("Generated shared secret: ", output_buf, *output_len);

  // Key deallocation
  err_code = nrf_crypto_ecc_private_key_free(&pri_key);
  if (err_code != NRF_SUCCESS) {
    return SEC_OP_FAILURE;
  }
  err_code = nrf_crypto_ecc_public_key_free(&pub_key);
  if (err_code != NRF_SUCCESS) {
    return SEC_OP_FAILURE;
  }

  //***************************************************//
  return SEC_OP_SUCCESS;
}