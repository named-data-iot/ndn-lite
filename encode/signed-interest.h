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

static inline void
ndn_signed_interest_set_signature_nounce(ndn_interest_t* interest, uint32_t nounce)
{
  interest->signature_nounce = nounce;
}

static inline void
ndn_signed_interest_set_signature_timestamp(ndn_interest_t* interest, uint32_t timestamp)
{
  interest->signature_timestamp = timestamp;
}

// this function will automatically set signature info and signature value
int
ndn_signed_interest_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_interest_t* interest);


// this function will automatically set signature info and signature value
int
ndn_signed_interest_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_interest_t* interest,
                                          const ndn_name_t* producer_identity,
                                          const ndn_ecc_prv_t* prv_key);

// this function will automatically set signature info and signature value
int
ndn_signed_interest_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_interest_t* interest,
                                         const ndn_name_t* producer_identity,
                                         const ndn_hmac_key_t* hmac_key);

int
ndn_signed_interest_digest_verify(const ndn_interest_t* interest);

int
ndn_signed_interest_ecdsa_verify(const ndn_interest_t* interest,
                                 const ndn_ecc_pub_t* pub_key);

int
ndn_signed_interest_hmac_verify(const ndn_interest_t* interest,
                                const ndn_hmac_key_t* hmac_key);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_SIGNED_INTEREST_H
