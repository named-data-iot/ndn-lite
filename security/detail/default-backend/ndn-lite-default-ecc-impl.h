/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_DEFAULT_ECC_IMPL_H
#define NDN_LITE_DEFAULT_ECC_IMPL_H

#include <stddef.h>
#include <stdint.h>
#include "sec-lib/tinycrypt/tc_ecc.h"
#include "sec-lib/micro-ecc/uECC.h"

int
ndn_lite_default_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                              const uint8_t* sig_value, uint32_t sig_size,
                              const uint8_t* pub_key_value,
                              uint32_t pub_key_size, uint8_t ecdsa_type);

int
ndn_lite_default_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
                            uint8_t* output_value, uint32_t output_max_size,
                            const uint8_t* prv_key_value, uint32_t prv_key_size,
                            uint8_t ecdsa_type, uint32_t* output_used_size);

int
ndn_lite_default_ecc_dh(uint8_t* ecc_pub, uint8_t* ecc_prv,
                        uint8_t curve_type, uint8_t* output, uint32_t output_size);

int
ndn_lite_default_make_ecc_key(uint8_t* ecc_pub, uint32_t* pub_size,
                              uint8_t* ecc_prv, uint32_t* prv_size, uint8_t curve_type);

#endif // NDN_LITE_DEFAULT_ECC_IMPL_H
