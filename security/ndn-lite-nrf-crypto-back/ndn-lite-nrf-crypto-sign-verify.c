
#include "../ndn-lite-sec-config.h"

#ifdef NDN_LITE_SEC_BACKEND_SIGN_VERIFY_NRF_CRYPTO

#include "../sign-verify.h"

#include "../../adaptation/ndn-nrf-ble-adaptation/logger.h"

//#include "boards.h"
//#include "nrf_assert.h"
//#include "nrf_crypto.h"
//#include "nrf_crypto_hash.h"
//#include "nrf_log.h"
//#include "nrf_log_ctrl.h"
//#include "nrf_log_default_backends.h"
//
//#include "app_error.h"
//#include "mem_manager.h"
//#include "nrf_assert.h"
//#include "nrf_crypto.h"
//#include "nrf_crypto_ecc.h"
//#include "nrf_crypto_ecdh.h"
//#include "nrf_crypto_error.h"
//#include "nrf_log.h"
//#include "nrf_log_ctrl.h"
//#include "nrf_log_default_backends.h"
//#include "sdk_common.h"
//#include <stdbool.h>
//#include <stdint.h>

#include "../sec-lib/micro-ecc/uECC.h"
#include "../../../app-support/bootstrapping/secure-sign-on-files/secure-sign-on/variants/basic/security/detail/detail-sha256/sha256-nrf-crypto-impl.h"
#include "../../../app-support/bootstrapping/secure-sign-on-files/secure-sign-on/variants/basic/security/sign-on-basic-sec-consts.h"

#ifndef FEATURE_PERIPH_HWRNG
typedef struct uECC_SHA256_HashContext {
  uECC_HashContext uECC;
  nrf_crypto_hash_context_t ctx;
} uECC_SHA256_HashContext;

static void
_init_sha256(const uECC_HashContext *base)
{
  uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
  nrf_crypto_hash_init(&context->ctx, &g_nrf_crypto_hash_sha256_info);
}

static void
_update_sha256(const uECC_HashContext *base,
               const uint8_t *message,
               unsigned message_size)
{
  uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
  nrf_crypto_hash_update(&context->ctx, message, message_size);
}

static void
_finish_sha256(const uECC_HashContext *base, uint8_t *hash_result)
{
  uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
  size_t dummy_size;
  nrf_crypto_hash_finalize(&context->ctx, hash_result, &dummy_size);
}
#endif

static void
sha256(const uint8_t* data, size_t datalen, uint8_t* hash_result)
{

  uint16_t data_size = (uint16_t) datalen;
  if (sign_on_basic_nrf_crypto_gen_sha256_hash(data, data_size, hash_result) != SEC_OP_SUCCESS) {
    APP_LOG("In ndn-lite-nrf-crypto-sign-verify.c, sign_on_basic_nrf_crypto_gen_sha256_hash failed.\n");
  }

//  // taken from the "hash" example of the SDK
//  //**************************************//
//  nrf_crypto_hash_sha256_digest_t ext_digest;
//  const uint16_t ext_digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;
//
//  nrf_crypto_hash_context_t ext_hash_context;
//
//  //**************************************//
//
//  // need to calculate N2 pub digest here
//  // taken from the "hash" example of the SDK
//  //**************************************//
//  //  // Integrated version
//  ret_code_t err_code;
//  size_t current_digest_len = (size_t) ext_digest_len;
//  err_code = nrf_crypto_hash_calculate(
//      &ext_hash_context,              // Context or NULL to allocate internally
//      &g_nrf_crypto_hash_sha256_info, // Info structure configures hash mode
//      data,                           // Input buffer
//      datalen,                        // Input size
//      ext_digest,                     // Result buffer
//      &current_digest_len);           // Result size
//  if (err_code != NRF_SUCCESS)
//    APP_LOG("in ndn-lite-sign-verify.c (nrf crypto backend), nrf_crypto_hash_calculate failed, error "
//            "code: %d.\n", err_code);
//
//  APP_LOG_HEX("in ndn-lite-sign-verify.c, sha256 function, original value:", data, datalen);
//  APP_LOG_HEX("in ndn-lite-sign-verify.c, sha256 function, generated hash:", ext_digest, current_digest_len);
//
//  //**************************************//
//  memcpy(hash_result, ext_digest, current_digest_len);
}

static void
hmac_sha256(const uint8_t* key, unsigned int key_size,
            const void* data, unsigned int data_length,
            uint8_t* hmac_result)
{

  // taken from the "hmac" example of the SDK
  //******************************************************//
  nrf_crypto_hash_sha256_digest_t m_digest;
  static nrf_crypto_hmac_context_t m_context;

  //******************************************************//

  // taken from the "hmac" example of the SDK"
  //*****************************************************//

  size_t digest_len = sizeof(m_digest);
  size_t key_len = key_size;

  APP_LOG("HMAC example started.\n");

  // Initialize frontend (which also initializes backend).
  ret_code_t err_code = nrf_crypto_hmac_init(
      &m_context,
      &g_nrf_crypto_hmac_sha256_info,
      key,
      key_len);
  if (err_code != NRF_SUCCESS)
    APP_LOG("in ndn-lite-sign-verify.c (nrf crypto backend), nrf_crypto_hmac_init failed.\n");

  // Push all data in one go (could be done repeatedly)
  err_code = nrf_crypto_hmac_update(&m_context, data, data_length);
  if (err_code != NRF_SUCCESS)
    APP_LOG("in ndn-lite-sign-verify.c (nrf crypto backend), nrf_crypto_hmac_update failed.\n");

  // Finish calculation
  err_code = nrf_crypto_hmac_finalize(&m_context, m_digest, &digest_len);
  if (err_code != NRF_SUCCESS)
    APP_LOG("in ndn-lite-sign-verify.c (nrf crypto backend), nrf_crypto_hmac_finalize failed.\n");
}

int
ndn_signer_sha256_sign(const uint8_t* input_value, uint32_t input_size,
                       uint8_t* output_value, uint32_t output_max_size,
                       uint32_t* output_used_size)
{
  if (output_max_size < 32)
    return NDN_OVERSIZE;
  sha256(input_value, input_size, output_value);
  *output_used_size = 32;
  return 0;
}

int
ndn_signer_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
                      uint8_t* output_value, uint32_t output_max_size,
                      const uint8_t* prv_key_value, uint32_t prv_key_size,
                      uint8_t ecdsa_type, uint32_t* output_used_size)
{
  if (output_max_size < 64)
    return NDN_OVERSIZE;
  if (prv_key_size > 32)
    return NDN_SEC_WRONG_KEY_SIZE;

  uint8_t input_hash[32] = {0};
  sha256(input_value, input_size, input_hash);
  uECC_Curve curve;
  switch (ecdsa_type) {
  case NDN_ECDSA_CURVE_SECP160R1:
    curve = uECC_secp160r1();
    break;
  case NDN_ECDSA_CURVE_SECP192R1:
    curve = uECC_secp192r1();
    break;
  case NDN_ECDSA_CURVE_SECP224R1:
    curve = uECC_secp224r1();
    break;
  case NDN_ECDSA_CURVE_SECP256R1:
    curve = uECC_secp256r1();
    break;
  case NDN_ECDSA_CURVE_SECP256K1:
    curve = uECC_secp256k1();
    break;
  default:
    return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  }
  int ecc_sign_result = 0;

#ifndef FEATURE_PERIPH_HWRNG
  // allocate memory on heap to avoid stack overflow
  uint8_t tmp[32 + 32 + 64];
  uECC_SHA256_HashContext HashContext;
  uECC_SHA256_HashContext* ctx = &HashContext;
  ctx->uECC.init_hash = &_init_sha256;
  ctx->uECC.update_hash = &_update_sha256;
  ctx->uECC.finish_hash = &_finish_sha256;
  ctx->uECC.block_size = 64;
  ctx->uECC.result_size = 32;
  ctx->uECC.tmp = tmp;
  ecc_sign_result = uECC_sign_deterministic(prv_key_value, input_hash, sizeof(input_hash),
                                            &ctx->uECC, output_value, curve);
#else
  ecc_sign_result = uECC_sign(prv_key_value, input_hash, sizeof(input_hash),
                              output_value, curve);
#endif
  if (ecc_sign_result == 0)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  *output_used_size = 64;
  return 0;
}

int
ndn_signer_hmac_sign(const uint8_t* input_value, uint32_t input_size,
                     uint8_t* output_value, uint32_t output_max_size,
                     const uint8_t* key_value, uint32_t key_size,
                     uint32_t* output_used_size)
{
  if (output_max_size < 32)
    return NDN_OVERSIZE;
  hmac_sha256(key_value, key_size, input_value, input_size, output_value);
  *output_used_size = 32;
  return 0;
}

int
ndn_verifier_sha256_verify(const uint8_t* input_value, uint32_t input_size,
                           const uint8_t* sig_value, uint32_t sig_size)
{
  if (sig_size != 32)
    return NDN_SEC_WRONG_SIG_SIZE;
  uint8_t input_hash[32] = {0};
  sha256(input_value, input_size, input_hash);
  if (memcmp(input_hash, sig_value, sizeof(input_hash)) != 0)
    return -1;
  else
    return 0;
}

int
ndn_verifier_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                          const uint8_t* sig_value, uint32_t sig_size,
                          const uint8_t* pub_key_value,
                          uint32_t pub_key_size, uint8_t ecdsa_type)
{
  if (sig_size > 64)
    return NDN_SEC_WRONG_SIG_SIZE;
  if (pub_key_size > 64)
    return NDN_SEC_WRONG_KEY_SIZE;

  uint8_t input_hash[32] = {0};
  sha256(input_value, input_size, input_hash);
  uECC_Curve curve;
  switch(ecdsa_type){
  case NDN_ECDSA_CURVE_SECP160R1:
    curve = uECC_secp160r1();
    break;
  case NDN_ECDSA_CURVE_SECP192R1:
    curve = uECC_secp192r1();
    break;
  case NDN_ECDSA_CURVE_SECP224R1:
    curve = uECC_secp224r1();
    break;
  case NDN_ECDSA_CURVE_SECP256R1:
    curve = uECC_secp256r1();
    break;
  case NDN_ECDSA_CURVE_SECP256K1:
    curve = uECC_secp256k1();
    break;
  default:
    return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  }
  if (uECC_verify(pub_key_value, input_hash, sizeof(input_hash),
                  sig_value, curve) == 0)
    return -1;
  else
    return 0;
}

int
ndn_verifier_hmac_verify(const uint8_t* input_value, uint32_t input_size,
                         const uint8_t* sig_value, uint32_t sig_size,
                         const uint8_t* key_value, uint32_t key_size)
{
  if (sig_size != 32)
    return NDN_SEC_WRONG_SIG_SIZE;

  uint8_t input_hmac[32] = {0};
  hmac_sha256(key_value, key_size, input_value, input_size, input_hmac);
  if (memcmp(input_hmac, sig_value, sizeof(input_hmac)) != 0)
    return -1;
  else
    return 0;
}

#endif // NDN_LITE_SEC_BACKEND_SIGN_VERIFY_NRF_CRYPTO
