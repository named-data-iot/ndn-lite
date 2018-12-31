/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ECC_MICROECC_IMPL_H
#define ECC_MICROECC_IMPL_H

#include <stddef.h>
#include <stdint.h>

int ndn_lite_microecc_gen_sha256_ecdsa_sig(
    const uint8_t *pri_key_raw,
    const uint8_t *payload, uint16_t payload_len,
    uint8_t *output_buf, uint16_t output_buf_len, uint16_t *output_len);

#endif // ECC_MICROECC_IMPL_H