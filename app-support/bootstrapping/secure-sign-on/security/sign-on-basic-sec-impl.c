/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sign-on-basic-sec-impl.h"

#include "sign-on-basic-sec-consts.h"

#include "../../../../adaptation/ndn-nrf-ble-adaptation/logger.h"

#include "../../../../ndn-enums.h"
#include "../../../../ndn-error-code.h"

#include "../../../../security/ndn-lite-aes.h"
#include "../../../../security/ndn-lite-ecc.h"
#include "../../../../security/ndn-lite-hmac.h"
#include "../../../../security/ndn-lite-sha.h"
#include "../../../../security/ndn-lite-rng.h"
#include "../../../../security/ndn-lite-crypto-key.h"

static const uint32_t sign_on_basic_arbitrary_key_id = 1337;

// this is a temporary function to convert a uECC curve to an ndn-lite
// ecdsa curve enum; this really should not be here, because none of these function
// interfaces should have a uECC dependency in them, but I will fix this later
int get_ndn_lite_curve(uECC_Curve curve) {
    if (curve == uECC_secp256r1()) {
      return NDN_ECDSA_CURVE_SECP256R1;
    }
    return -1;
}

int sign_on_basic_gen_sha256_hash(const uint8_t *payload, uint32_t payload_len, uint8_t *output) {
  if (ndn_sha256(payload, payload_len, output) == NDN_SUCCESS) {
    return SIGN_ON_BASIC_SEC_OP_SUCCESS;
  }
  return SIGN_ON_BASIC_SEC_OP_FAILURE;
}

int sign_on_basic_aes_cbc_decrypt(uint8_t *key, uint32_t key_len, 
                                           const uint8_t *encrypted_payload, uint32_t encrypted_payload_len,
                                           uint8_t *decrypted_payload, uint32_t decrypted_payload_buf_len) {

  uint8_t aes_iv[NDN_SEC_AES_IV_LENGTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint8_t decrypted_payload_buf_len_byte = (uint8_t) decrypted_payload_buf_len;
  uint8_t key_len_byte = (uint8_t) key_len;
  uint8_t encrypted_payload_copy[encrypted_payload_len + NDN_SEC_AES_IV_LENGTH];
  uint32_t encrypted_payload_copy_len = encrypted_payload_len + NDN_SEC_AES_IV_LENGTH;
  uint8_t encrypted_payload_copy_len_byte = (uint8_t) encrypted_payload_copy_len;
  memcpy(encrypted_payload_copy, aes_iv, NDN_SEC_AES_IV_LENGTH);
  memcpy(encrypted_payload_copy + NDN_SEC_AES_IV_LENGTH, encrypted_payload, encrypted_payload_len);
  APP_LOG("Length of encrypted payload being passed into ndn_aes_cbc_decrypt: %d\n", 
          encrypted_payload_copy_len_byte);
  APP_LOG_HEX("Value of key being used to decrypt KD pri:", key,
              SIGN_ON_BASIC_AES_KEY_MAX_LENGTH);
  APP_LOG_HEX("Value being decrypted to get KD pri:", encrypted_payload_copy, encrypted_payload_copy_len);

  ndn_aes_key_t aes_key;
  ndn_aes_key_init(&aes_key, key, SIGN_ON_BASIC_AES_KEY_MAX_LENGTH, sign_on_basic_arbitrary_key_id);

  // according to Tinycrypt's comments in tc_cbc_mode.h, I need to make sure IV and
  // cipher text are contiguous in the buffer passed in for decryption
  
  if (ndn_aes_cbc_decrypt(encrypted_payload_copy, 
                      encrypted_payload_copy_len_byte, decrypted_payload,
                      decrypted_payload_buf_len_byte, encrypted_payload_copy, 
                      &aes_key) != NDN_SUCCESS) {
    return SIGN_ON_BASIC_SEC_OP_FAILURE;
  }
  return SIGN_ON_BASIC_SEC_OP_SUCCESS;
}

int sign_on_basic_vrfy_hmac_sha256_sig(const uint8_t *payload, uint32_t payload_len,
                                       const uint8_t *sig, uint32_t sig_len,
                                       const uint8_t *key, uint32_t key_len) {
  ndn_hmac_key_t hmac_key;
  ndn_hmac_key_init(&hmac_key, key, key_len, sign_on_basic_arbitrary_key_id);


  if (ndn_hmac_verify(payload, payload_len, sig, sig_len, &hmac_key) == NDN_SUCCESS) {
    return SIGN_ON_BASIC_SEC_OP_SUCCESS;
  }
  return SIGN_ON_BASIC_SEC_OP_FAILURE;
}

int sign_on_basic_gen_sha256_ecdsa_sig(const uint8_t *pri_key_raw, uECC_Curve curve,
                                       const uint8_t *payload, uint32_t payload_len,
                                       uint8_t *output_buf, uint32_t output_buf_len, 
                                       uint32_t *output_len) {
  ndn_ecc_set_rng(ndn_rng);
  int ndn_ecc_curve = get_ndn_lite_curve(curve);
  if (ndn_ecc_curve == -1) {
    APP_LOG("in sign_on_basic_gen_ecdh_shared_secret, unrecognized curve.\n");
    return SIGN_ON_BASIC_SEC_OP_FAILURE;
  }

  uint32_t pri_key_raw_len = (uint32_t) uECC_curve_private_key_size(curve);

  ndn_ecc_prv_t ecc_prv_key;
  ndn_ecc_prv_init(&ecc_prv_key, pri_key_raw, pri_key_raw_len, ndn_ecc_curve, sign_on_basic_arbitrary_key_id);

  
  APP_LOG("Value of pri_key_raw_len in sign_on_basic_gen_sha256_ecdsa_sig: %d\n", pri_key_raw_len);
  if (ndn_ecdsa_sign(payload, payload_len, output_buf, output_buf_len, &ecc_prv_key, 
                     ndn_ecc_curve, output_len) != NDN_SUCCESS) {
    return SIGN_ON_BASIC_SEC_OP_FAILURE;
  }
  APP_LOG_HEX("In sign_on_basic_gen_sha256_ecdsa_sig, value of signature "
              "generated by ndn_ecdsa_sign:", output_buf, *output_len);
  return SIGN_ON_BASIC_SEC_OP_SUCCESS;
}

int sign_on_basic_gen_ecdh_shared_secret(const uint8_t *pub_key_raw, uint32_t pub_key_raw_len,
                                         const uint8_t *pri_key_raw, uint32_t pri_key_raw_len,
                                         uECC_Curve curve,
                                         uint8_t *output_buf, uint32_t output_buf_len, 
                                         uint32_t *output_len) {
  ndn_ecc_set_rng(ndn_rng);
  int ndn_ecc_curve = get_ndn_lite_curve(curve);
  if (ndn_ecc_curve == -1) {
    APP_LOG("in sign_on_basic_gen_ecdh_shared_secret, unrecognized curve.\n");
    return SIGN_ON_BASIC_SEC_OP_FAILURE;
  }
  ndn_ecc_pub_t ecc_pub_key;
  ndn_ecc_prv_t ecc_prv_key;
  ndn_ecc_pub_init(&ecc_pub_key, pub_key_raw, pub_key_raw_len, ndn_ecc_curve, sign_on_basic_arbitrary_key_id);
  ndn_ecc_prv_init(&ecc_prv_key, pri_key_raw, pri_key_raw_len, ndn_ecc_curve, sign_on_basic_arbitrary_key_id);
  if (ndn_ecc_dh_shared_secret(&ecc_pub_key, &ecc_prv_key, 
                               ndn_ecc_curve, 
                               output_buf, output_buf_len) != NDN_SUCCESS) {
    return SIGN_ON_BASIC_SEC_OP_FAILURE;
  }
  *output_len = pri_key_raw_len;
  return SIGN_ON_BASIC_SEC_OP_SUCCESS;
}

int sign_on_basic_gen_ec_keypair(uint8_t *pub_key_buf, uint32_t pub_key_buf_len, 
                                 uint32_t *pub_key_output_len,
                                 uint8_t *pri_key_buf, uint32_t pri_key_buf_len, 
                                 uint32_t *pri_key_output_len,
                                 uECC_Curve curve) {
    ndn_ecc_set_rng(ndn_rng);

    int ndn_ecc_curve = get_ndn_lite_curve(curve);
    if (ndn_ecc_curve == -1) {
      APP_LOG("in sign_on_basic_gen_ec_keypair, unrecognized curve.\n");
      return SIGN_ON_BASIC_SEC_OP_FAILURE;
    }
    ndn_ecc_pub_t ecc_pub_key;
    ndn_ecc_prv_t ecc_prv_key;
    if (ndn_ecc_make_key(&ecc_pub_key, &ecc_prv_key, ndn_ecc_curve, sign_on_basic_arbitrary_key_id) 
        != NDN_SUCCESS) {
      printf("in sign_on_basic_gen_ec_keypair, ndn_ecc_make_key failed.\n");
      return SIGN_ON_BASIC_SEC_OP_FAILURE;
    }

    if (ecc_pub_key.abs_key.key_size > pub_key_buf_len) {
      return SIGN_ON_BASIC_SEC_OP_FAILURE;
    }
    if (ecc_prv_key.abs_key.key_size > pri_key_buf_len) {
      return SIGN_ON_BASIC_SEC_OP_FAILURE;
    }

    memcpy(pub_key_buf, ecc_pub_key.abs_key.key_value, ecc_pub_key.abs_key.key_size);
    *pub_key_output_len = ecc_pub_key.abs_key.key_size;
    memcpy(pri_key_buf, ecc_prv_key.abs_key.key_value, ecc_prv_key.abs_key.key_size);
    *pri_key_output_len = ecc_prv_key.abs_key.key_size;

    return SIGN_ON_BASIC_SEC_OP_SUCCESS;
}