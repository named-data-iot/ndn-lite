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

// Includes from the "hash" example of the SDK
//**************************************//
#include "boards.h"
#include "nrf_assert.h"
#include "nrf_crypto.h"
#include "nrf_crypto_hash.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
//**************************************//

int
ndn_lite_nrf_crypto_gen_sha256_hash(const uint8_t *payload, uint16_t payload_len, uint8_t *output);

#endif // SHA_256_NRF_CRYPTO_IMPL_H
