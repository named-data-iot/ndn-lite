/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef HMAC_NRF_CRYPTO_IMPL_H
#define HMAC_NRF_CRYPTO_IMPL_H

// Includes from the "ecdh" example of the SDK
//**************************************//
#include "app_error.h"
#include "mem_manager.h"
#include "nrf_assert.h"
#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_ecdh.h"
#include "nrf_crypto_error.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "sdk_common.h"
#include <stdbool.h>
#include <stdint.h>

//**************************************//

bool sign_on_basic_nrf_crypto_vrfy_hmac_sha256_sig(const uint8_t *payload, uint16_t payload_len,
                               const uint8_t *sig, uint16_t sig_len,
                               const uint8_t *key, uint16_t key_len);

#endif // HMAC_NRF_CRYPTO_IMPL_H