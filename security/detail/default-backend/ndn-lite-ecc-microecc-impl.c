/*
 * Copyright (C) 2018 Edward Lu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-lite-ecc-microecc-impl.h"
#include "ndn-lite-sha256-tinycrypt-impl.h"
#include "../../../ndn-error-code.h"
#include "../../../ndn-constants.h"
#include "../../../ndn-enums.h"
#include "../sec-lib/micro-ecc/uECC.h"
#include "../sec-lib/tinycrypt/tc_hmac.h"

#ifndef FEATURE_PERIPH_HWRNG
typedef struct uECC_SHA256_HashContext {
 uECC_HashContext uECC;
 struct tc_sha256_state_struct ctx;
} uECC_SHA256_HashContext;

static void
_init_sha256(const uECC_HashContext *base)
{
 uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
 tc_sha256_init(&context->ctx);
}

static void
_update_sha256(const uECC_HashContext *base,
              const uint8_t *message,
              unsigned message_size)
{
 uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
 tc_sha256_update(&context->ctx, message, message_size);
}

static void
_finish_sha256(const uECC_HashContext *base, uint8_t *hash_result)
{
 uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
 tc_sha256_final(hash_result, &context->ctx);
}
#endif

int
ndn_lite_ecdsa_verify_microecc(const uint8_t* input_value, uint32_t input_size,
                               const uint8_t* sig_value, uint32_t sig_size,
                               const uint8_t* pub_key_value,
                               uint32_t pub_key_size, uint8_t ecdsa_type)
{
  if (sig_size > NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE)
    return NDN_SEC_WRONG_SIG_SIZE;
  if (pub_key_size > NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE)
    return NDN_SEC_WRONG_KEY_SIZE;

  uint8_t input_hash[NDN_SEC_SHA256_HASH_SIZE] = {0};
  if (ndn_lite_sha256_tinycrypt(input_value, input_size, input_hash) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
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
                  sig_value, curve) == 0) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  else
    return NDN_SUCCESS;
}

int
ndn_lite_ecdsa_sign_microecc(const uint8_t* input_value, uint32_t input_size,
                             uint8_t* output_value, uint32_t output_max_size,
                             const uint8_t* prv_key_value, uint32_t prv_key_size,
                             uint8_t ecdsa_type, uint32_t* output_used_size)
{
  if (output_max_size < NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE)
    return NDN_OVERSIZE;
  if (prv_key_size > NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE)
    return NDN_SEC_WRONG_KEY_SIZE;

  uint8_t input_hash[NDN_SEC_SHA256_HASH_SIZE] = {0};
  if (ndn_lite_sha256_tinycrypt(input_value, input_size, input_hash) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
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
  uint8_t tmp[NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE +
              NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE +
              NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE];
  uECC_SHA256_HashContext HashContext;
  uECC_SHA256_HashContext* ctx = &HashContext;
  ctx->uECC.init_hash = &_init_sha256;
  ctx->uECC.update_hash = &_update_sha256;
  ctx->uECC.finish_hash = &_finish_sha256;
  ctx->uECC.block_size = NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE;
  ctx->uECC.result_size = NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE;
  ctx->uECC.tmp = tmp;
  ecc_sign_result = uECC_sign_deterministic(prv_key_value, input_hash, sizeof(input_hash),
                                            &ctx->uECC, output_value, curve);
#else
  ecc_sign_result = uECC_sign(prv_key_value, input_hash, sizeof(input_hash),
                              output_value, curve);
#endif
  if (ecc_sign_result == 0) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  *output_used_size = NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE;
  return NDN_SUCCESS;
}
