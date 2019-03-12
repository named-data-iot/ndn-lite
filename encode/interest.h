/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_INTEREST_H
#define NDN_ENCODING_INTEREST_H

#include "name.h"
#include "signature.h"
#include "../security/ndn-lite-crypto-key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to represent the Interest parameters element.
 */
typedef struct interest_params {
  uint8_t value[NDN_INTEREST_PARAMS_BUFFER_SIZE];
  uint32_t size;
} interest_params_t;

/**
 * The structure to represent an NDN Interest packet.
 */
typedef struct ndn_interest {
  /**
   * The name of the Interest.
   */
  ndn_name_t name;
  /**
   * The nonce of the Interest.
   */
  uint32_t nonce;
  /**
   * The lifetime of the Interest.
   */
  uint64_t lifetime;

  uint8_t enable_CanBePrefix;
  uint8_t enable_MustBeFresh;

  /**
   * The Parameters of the Interest. Used when enable_Parameters > 0.
   */
  interest_params_t parameters;
  uint8_t enable_Parameters;

  /**
   * The HopLimit of the Interest. Used when enable_HopLimit > 0.
   */
  uint8_t hop_limit;
  uint8_t enable_HopLimit;

  uint8_t is_SignedInterest;
  /**
   * The signature structure. Used when is_SignedInterest > 0.
   */
  ndn_signature_t signature;
} ndn_interest_t;

/**
 * Init an Interest packet.
 * This function or ndn_interest_from_name() should be invoked
 * whenever a new ndn_interest_t is created.
 * @param interest. Output. The Interest to be inited.
 */
static inline void
ndn_interest_init(ndn_interest_t* interest)
{
  interest->enable_CanBePrefix = 0;
  interest->enable_MustBeFresh = 0;
  interest->enable_HopLimit = 0;
  interest->enable_Parameters = 0;
  interest->is_SignedInterest = 0;

  interest->nonce = 0;
  interest->lifetime = NDN_DEFAULT_INTEREST_LIFETIME;
  interest->hop_limit = 0;
}

/**
 * Init an Interest packet from a @param name.
 * This function or ndn_interest_init() should be invoked
 * whenever a new ndn_interest_t is created.
 * @param interest. Output. The Interest to be inited.
 * @param name. Input. The Interest name.
 */
static inline void
ndn_interest_from_name(ndn_interest_t* interest, const ndn_name_t* name)
{
  interest->name = *name;

  interest->enable_CanBePrefix = 0;
  interest->enable_MustBeFresh = 0;
  interest->enable_HopLimit = 0;
  interest->enable_Parameters = 0;
  interest->is_SignedInterest = 0;

  interest->nonce = 0;
  interest->lifetime = NDN_DEFAULT_INTEREST_LIFETIME;
  interest->hop_limit = 0;
}

/**
 * Decode an Interest TLV block into an ndn_interest_t.
 * @param interest. Output. The Interest to which the TLV block will be decoded.
 * @param block_value. Input. The Interest TLV block buffer.
 * @param block_size. Input. The size of the Interest TLV block buffer.
 * @return 0 if decoding is successful.
 */
int
ndn_interest_from_block(ndn_interest_t* interest, const uint8_t* block_value, uint32_t block_size);

/**
 * Set CanBePrefix flag of the Interest.
 * @param interest. Output. The Interest whose flag will be set.
 * @param can_be_prefix. Input. CanBePrefix is set if can_be_prefix is larger than 0.
 */
static inline void
ndn_interest_set_CanBePrefix(ndn_interest_t* interest, uint8_t can_be_prefix)
{
  interest->enable_CanBePrefix = (can_be_prefix > 0 ? 1 : 0);
}

/**
 * Set MustBeFresh flag of the Interest.
 * @param interest. Output. The Interest whose flag will be set.
 * @param can_be_prefix. Input. MustBeFresh is set if must_be_fresh is larger than 0.
 */
static inline void
ndn_interest_set_MustBeFresh(ndn_interest_t* interest, uint8_t must_be_fresh)
{
  interest->enable_MustBeFresh = (must_be_fresh > 0 ? 1 : 0);
}

/**
 * Set HopLimit element of the Interest.
 * @param interest. Output. The Interest whose HopLimit will be set.
 * @param hop. Input. The value of the HopLimit.
 */
static inline void
ndn_interest_set_HopLimit(ndn_interest_t* interest, uint8_t hop)
{
  interest->enable_HopLimit = 1;
  interest->hop_limit = hop;
}

/**
 * Set Parameters element of the Interest.
 * @param interest. Output. The Interest whose Parameters will be set.
 * @param params_value. Input. The interest parameters value (V).
 * @param params_size. Input. The size of the interest parameters value (V).
 * @return 0 if there is no error.
 */
static inline int
ndn_interest_set_Parameters(ndn_interest_t* interest,
                            const uint8_t* params_value, uint32_t params_size)
{
  if (params_size > NDN_INTEREST_PARAMS_BUFFER_SIZE)
    return NDN_OVERSIZE;
  interest->enable_Parameters = 1;
  memcpy(interest->parameters.value, params_value, params_size);
  interest->parameters.size = params_size;
  return 0;
}

/**
 * Encode the Interest into wire format (TLV block).
 * This function is only used for unsigned Interest.
 * @param encoder. Output. The encoder who keeps the encoding result and the state.
 * @param interest. Input. The Interest to be encoded.
 * @return 0 if there is no error.
 */
int
ndn_interest_tlv_encode(ndn_encoder_t* encoder, const ndn_interest_t* interest);

/**
 * Compare two encoded Interests' names.
 * @param lhs_block_value. Input. Left-hand-side encoded Interest block value.
 * @param lhs_block_size. Input. Left-hand-side encoded Interest block size.
 * @param rhs_block_value. Input. Right-hand-side encoded Interest block value.
 * @param rhs_block_size. Input. Right-hand-side encoded Interest block size.
 * @return 0 if @p lhs == @p rhs.
 * @return 1, if @p lhs > @p rhs and @p rhs is not a prefix of @p lhs.
 * @return 2, if @p lhs > @p rhs and @p rhs is a proper prefix of @p lhs.
 * @return -1, if @p lhs < @p rhs and @p lhs is not a prefix of @p rhs.
 * @return -2, if @p lhs < @p rhs and @p lhs is a proper prefix of @p rhs.
 */
int
ndn_interest_compare_block(ndn_decoder_t* lhs_decoder, ndn_decoder_t* rhs_decoder);

/**
 * Compare two encoded Interests' names.
 * @param lhs_block_value. Input. Left-hand-side encoded Interest block value.
 * @param lhs_block_size. Input. Left-hand-side encoded Interest block size.
 * @param rhs_block_value. Input. Right-hand-side encoded Interest block value.
 * @param rhs_block_size. Input. Right-hand-side encoded Interest block size.
 * @return 0 if @p lhs == @p rhs.
 * @return 1, if @p lhs > @p rhs and @p rhs is not a prefix of @p lhs.
 * @return 2, if @p lhs > @p rhs and @p rhs is a proper prefix of @p lhs.
 * @return -1, if @p lhs < @p rhs and @p lhs is not a prefix of @p rhs.
 * @return -2, if @p lhs < @p rhs and @p lhs is a proper prefix of @p rhs.
 */
int
ndn_interest_name_compare_block(ndn_decoder_t* interest_decoder, ndn_decoder_t* name_decoder);

/************************************************************/
/*  Ultra Lightweight Encoding Functions                    */
/************************************************************/
int
_interest_uri_tlv_probe_size(const char* uri, uint32_t len, uint32_t lifetime);

int
ndn_interest_uri_tlv_encode(ndn_encoder_t* encoder, const char* uri, uint32_t len,
                            uint32_t lifetime, uint32_t nonce);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_INTEREST_H
