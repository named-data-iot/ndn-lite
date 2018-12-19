/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef AES_NRF_CRYPTO_IMPL_H
#define AES_NRF_CRYPTO_IMPL_H

// Includes from the "aes" example of the SDK
//**************************************//
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_drv_clock.h"

#include "nrf_drv_power.h"

#include "app_error.h"
#include "app_util.h"

#include "boards.h"

#include "mem_manager.h"
#include "nrf_crypto.h"
#include "nrf_crypto_error.h"

//**************************************//

#include "../../../../../../../../../logger.h"

// taken from the "aes" example of the SDK
//*****************************************************//

#define NRF_CRYPTO_EXAMPLE_AES_MAX_TEXT_SIZE 120

int sign_on_basic_nrf_crypto_decrypt_aes_cbc_pkcs5pad(uint8_t *key, uint16_t key_len, 
    const uint8_t *encrypted_payload, uint16_t encrypted_payload_len,
    uint8_t *decrypted_payload, uint16_t *decrypted_payload_len);

//*****************************************************//

#endif // AES_NRF_CRYPTO_IMPL_H