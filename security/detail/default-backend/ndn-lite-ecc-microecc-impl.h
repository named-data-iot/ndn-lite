/*
 * Copyright (C) 2018 Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef ECC_MICROECC_IMPL_H
#define ECC_MICROECC_IMPL_H

#include <stddef.h>
#include <stdint.h>

int
ndn_lite_ecdsa_verify_microecc(const uint8_t* input_value, uint32_t input_size,
                               const uint8_t* sig_value, uint32_t sig_size,
                               const uint8_t* pub_key_value,
                               uint32_t pub_key_size, uint8_t ecdsa_type);

int
ndn_lite_ecdsa_sign_microecc(const uint8_t* input_value, uint32_t input_size,
                             uint8_t* output_value, uint32_t output_max_size,
                             const uint8_t* prv_key_value, uint32_t prv_key_size,
                             uint8_t ecdsa_type, uint32_t* output_used_size);

#endif // ECC_MICROECC_IMPL_H
