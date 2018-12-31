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

// taken from the "aes" example of the SDK
//*****************************************************//

int ndn_lite_aes_cbc_decrypt_nrf_crypto(const uint8_t* input_value, uint8_t input_size,
                                                  uint8_t* output_value, uint8_t output_size,
                                                  const uint8_t* aes_iv,
                                                  const uint8_t* key_value, uint8_t key_size);

//*****************************************************//

#endif // AES_NRF_CRYPTO_IMPL_H