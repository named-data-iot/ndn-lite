/*
 * Copyright (C) 2018 Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SHA_256_NRF_CRYPTO_IMPL_H
#define SHA_256_NRF_CRYPTO_IMPL_H

#include <stdint.h>

int
ndn_lite_nrf_crypto_sha256(const uint8_t *payload, uint16_t payload_len, uint8_t *output);

void
ndn_lite_nrf_crypto_sha_load_backend(void);

#endif // SHA_256_NRF_CRYPTO_IMPL_H
