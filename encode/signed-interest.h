/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_SIGNED_INTEREST_H
#define NDN_ENCODING_SIGNED_INTEREST_H

#include "interest.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_signed_interest {
  ndn_name_t name;
  uint8_t nounce[4];
  uint8_t lifetime[2];

  uint8_t enable_CanBePrefix;
  uint8_t enable_MustBeFresh;
  uint8_t enable_HopLimit;
  uint8_t enable_Parameters;

  interest_params_t parameters;
  uint8_t hop_limit;

  uint32_t signature_timestamp;
  uint32_t signature_nounce;
  ndn_signature_t signature;
} ndn_signed_interest_t;

uint32_t
ndn_signed_interest_probe_block_size();

uint32_t
ndn_signed_interest_probe_unsigned_block();


// this function should be invoked only after interest's signature
// info has been initialized
uint32_t
ndn_interest_probe_unsigned_block_size(ndn_signed_interest_t* interest, int flag);

int
ndn_interest_prepare_unsigned_block(ndn_encoder_t* encoder, ndn_signed_interest_t* interest, int flag);

// this function will automatically set signature info and signature value
int
ndn_interest_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_signed_interest_t* interest);

// this function will automatically set signature info and signature value
int
ndn_interest_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_signed_interest_t* interest,
                                   const ndn_name_t* producer_identity,
                                   const ndn_ecc_prv_t* prv_key);

// this function will automatically set signature info and signature value
int
ndn_interest_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_signed_interest_t* interest,
                                  const ndn_name_t* producer_identity,
                                  const ndn_hmac_key_t* hmac_key);

int
ndn_interest_tlv_decode_digest_verify(ndn_signed_interest_t* interest,
                                      const uint8_t* block_value, uint32_t block_size);

int
ndn_interest_tlv_decode_ecdsa_verify(ndn_signed_interest_t* interest,
                                     const uint8_t* block_value, uint32_t block_size,
                                     const ndn_ecc_pub_t* pub_key);

int
ndn_interest_tlv_decode_hmac_verify(ndn_signed_interest_t* interest,
                                    const uint8_t* block_value, uint32_t block_size,
                                    const ndn_hmac_key_t* hmac_key);


#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_SIGNED_INTEREST_H
