/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_LITE_ECC_TINYCRYPT_H
#define NDN_LITE_ECC_TINYCRYPT_H

#include "../../ndn-lite-crypto-key.h"

int ndn_lite_ecc_key_shared_secret_tinycrypt(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                                             uint8_t curve_type, uint8_t* output,
                                             uint32_t output_size);

int ndn_lite_ecc_key_make_key_tinycrypt(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                                        uint8_t curve_type, uint32_t key_id);

#endif // NDN_LITE_ECC_TINYCRYPT_H
