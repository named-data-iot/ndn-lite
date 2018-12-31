/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-lite-ecc-microecc-impl.h"

#include "../../../ndn-error-code.h"
#include "../../../ndn-constants.h"

#include "../detail-sha256/ndn-lite-sha256-nrf-crypto-impl.h"

#include "../detail-rng/ndn-lite-rng-nrf-crypto-impl.h"

#include "../detail-ecc/ndn-lite-ecc-nrf-crypto-impl.h"

#include <uECC.h>

int ndn_lite_microecc_gen_sha256_ecdsa_sig(
    const uint8_t *pri_key_raw,
    const uint8_t *payload, uint16_t payload_len,
    uint8_t *output_buf, uint16_t output_buf_len, uint16_t *output_len) {

  //APP_LOG("ndn_lite_microecc_gen_sha256_ecdsa_sig got called.\n");

  uint8_t pri_key[32];

  for (int i = 0; i < 32; i++) {
    pri_key[i] = pri_key_raw[32 - 1 - i];
  }

  //APP_LOG_HEX("Bytes of original private key: ", pri_key_raw, 32);
  //APP_LOG_HEX("Bytes of endian reversed private key: ", pri_key, 32);

  uint8_t payload_digest_original[NDN_SEC_SHA256_HASH_SIZE];
  if (ndn_lite_nrf_crypto_gen_sha256_hash(payload, payload_len, payload_digest_original) 
      != NDN_SUCCESS) {
    //APP_LOG("Failed to generate sha256 hash within ndn_lite_microecc_gen_sha256_ecdsa_sig\n");
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  uint8_t payload_digest[NDN_SEC_SHA256_HASH_SIZE];
  for (int i = 0; i < 32; i++) {
    payload_digest[i] = payload_digest_original[32 - 1 - i];
  }

  //APP_LOG_HEX("Original payload digest:", payload_digest_original, 32);
  //APP_LOG_HEX("Reversed payload digest:", payload_digest, 32);

  uECC_set_rng(ndn_lite_RNG);

  int signatureEncodingOffset = 8;

  int ret = uECC_sign(pri_key,
              payload_digest,
              NDN_SEC_SHA256_HASH_SIZE,
              output_buf + signatureEncodingOffset,
              uECC_secp256r1());

  if (ret != 1) {
    //APP_LOG("in ndn_lite_microecc_gen_sha256_ecdsa_sig, uECC_sign failed.\n");
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  uint8_t *sig_begin = output_buf + signatureEncodingOffset;
  uint8_t *sig_begin_2 = sig_begin + 32;

  //APP_LOG_HEX("Raw signature before reversing bytes:", sig_begin, 64);

  for (int i = 0; i < 16; i++) {
    uint8_t temp = sig_begin[32 - 1 - i];
    sig_begin[32 - 1 - i] = sig_begin[i];
    sig_begin[i] = temp;
  }

  for (int i = 0; i < 16; i++) {
    uint8_t temp = sig_begin_2[32 - 1 - i];
    sig_begin_2[32 - 1 - i] = sig_begin_2[i];
    sig_begin_2[i] = temp;
  }

  //APP_LOG_HEX("Raw signature after reversing bytes:", sig_begin, 64);

  ndn_lite_encodeSignatureBits(output_buf, output_len, uECC_secp256r1());

  return NDN_SUCCESS;

}