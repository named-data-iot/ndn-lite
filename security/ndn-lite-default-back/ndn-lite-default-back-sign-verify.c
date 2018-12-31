/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "../ndn-lite-sign-verify.h"
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

static void
sha256(const uint8_t* data, size_t datalen, uint8_t* hash_result)
{
  struct tc_sha256_state_struct s;
  (void)tc_sha256_init(&s);
  tc_sha256_update(&s, data, datalen);
  (void)tc_sha256_final(hash_result, &s);
}

static void
hmac_sha256(const uint8_t* key, unsigned int key_size,
            const void* data, unsigned int data_length,
            uint8_t* hmac_result)
{
  struct tc_hmac_state_struct h;
  (void)memset(&h, 0x00, sizeof(h));
  (void)tc_hmac_set_key(&h, key, key_size);
  (void)tc_hmac_init(&h);
  (void)tc_hmac_update(&h, data, data_length);
  (void)tc_hmac_final(hmac_result, TC_SHA256_DIGEST_SIZE, &h);
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
