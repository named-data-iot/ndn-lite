/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef ENCODING_INTEREST_H
#define ENCODING_INTEREST_H

#include "name.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct interest_params {
  uint8_t value[NDN_INTEREST_PARAMS_BUFFER_SIZE];
  uint32_t size;
} interest_params_t;


typedef struct ndn_interest {
  ndn_name_t name;
  uint8_t nounce[4];
  uint8_t lifetime[2];

  uint8_t enable_CanBePrefix;
  uint8_t enable_MustBeFresh;
  uint8_t enable_HopLimit;
  uint8_t enable_Parameters;

  interest_params_t parameters;
  uint8_t hop_limit;
} ndn_interest_t;


static inline void
ndn_interest_from_name(ndn_interest_t* interest, const ndn_name_t* name)
{
  interest->name = *name;
  interest->lifetime[0] = (DEFAULT_INTEREST_LIFETIME >> 8) & 0xFF;
  interest->lifetime[1] = DEFAULT_INTEREST_LIFETIME & 0xFF;

  interest->enable_CanBePrefix = 0;
  interest->enable_MustBeFresh = 0;
  interest->enable_HopLimit = 0;
  interest->enable_Parameters = 0;
}

// return 0 if decoding is successful
int
ndn_interest_from_block(ndn_interest_t* interest, const uint8_t* block_value, uint32_t block_size);

static inline void
ndn_interest_set_CanBePrefix(ndn_interest_t* interest, uint8_t can_be_prefix)
{
  interest->enable_CanBePrefix = (can_be_prefix > 0 ? 1 : 0);
}

static inline void
ndn_interest_set_MustBeFresh(ndn_interest_t* interest, uint8_t must_be_fresh)
{
  interest->enable_MustBeFresh = (must_be_fresh > 0 ? 1 : 0);
}

static inline void
ndn_interest_set_HopLimit(ndn_interest_t* interest, uint8_t hop)
{
  interest->enable_HopLimit = 1;
  interest->hop_limit = hop;
}

static inline void
ndn_interest_set_Parameters(ndn_interest_t* interest, const interest_params_t* parameters)
{
  interest->enable_Parameters = 1;
  interest->parameters = *parameters;
}

static inline uint32_t
ndn_interest_probe_block_size(const ndn_interest_t* interest)
{
  uint32_t interest_buffer_size = ndn_name_probe_block_size(&interest->name);
  if (interest->enable_CanBePrefix)
    interest_buffer_size += 2;
  if (interest->enable_MustBeFresh)
    interest_buffer_size += 2;
  if (interest->enable_HopLimit)
    interest_buffer_size += 3;
  if (interest->enable_Parameters)
    interest_buffer_size += encoder_probe_block_size(TLV_Parameters, interest->parameters.size);
  interest_buffer_size += 6; // nounce
  interest_buffer_size += 4; // lifetime
  return encoder_probe_block_size(TLV_Interest, interest_buffer_size);
}

// return the length of used block
int
ndn_interest_tlv_encode(const ndn_interest_t* interest, uint8_t* block_value, uint8_t block_max_size,
                        uint32_t* used_block_size);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_INTEREST_H
