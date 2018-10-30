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

typedef struct ndn_signer {
  const uint8_t* input_value;
  uint32_t input_size;
  uint8_t* output_value;
  uint32_t output_max_size;

  uint32_t output_used_size;
} ndn_signer_t;

static inline void
ndn_signer_init(ndn_signer_t* signer, const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_max_size)
{
  signer->input_value = input_value;
  signer->input_size = input_size;
  signer->output_value = output_value;
  signer->output_max_size = output_max_size;
  signer->output_used_size = 0;
}

int
ndn_signer_sha256_sign(ndn_signer_t* signer);

int
ndn_signer_ecdsa_sign(ndn_signer_t* signer, const uint8_t* prv_key_value, uint32_t prv_key_size,
                      uint8_t ecdsa_type);

int
ndn_signer_hmac_sign(ndn_signer_t* signer, const uint8_t* key_value, uint32_t key_size);

typedef struct ndn_verifier {
  const uint8_t* sig_value;
  uint32_t sig_size;
  const uint8_t* input_value;
  uint32_t input_size;
} ndn_verifier_t;

static inline void
ndn_verifier_init(ndn_verifier_t* verifier, const uint8_t* input_value, uint32_t input_size,
                  const uint8_t* sig_value, uint32_t sig_size)
{
  verifier->input_value = input_value;
  verifier->input_size = input_size;
  verifier->sig_value = sig_value;
  verifier->sig_size = sig_size;
}

int
ndn_verifier_sha256_verify(ndn_verifier_t* verifier);

int
ndn_verifier_ecdsa_verify(ndn_verifier_t* verifier, const uint8_t* pub_key_value, uint32_t pub_key_size,
                             uint8_t ecdsa_type);

int
ndn_verifier_hmac_verify(ndn_verifier_t* verifier, const uint8_t* key_value, uint32_t key_size);


#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_SIGN_VERIFY_H_
