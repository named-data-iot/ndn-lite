/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ECC_NRF_CRYPTO_IMPL_H
#define ECC_NRF_CRYPTO_IMPL_H

#include <stddef.h>

// Includes from the "ecdsa" example of the SDK
//**************************************//
#include "app_error.h"
#include "nrf_assert.h"
#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_ecdsa.h"
#include "nrf_crypto_error.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "sdk_common.h"
//**************************************//

// Includes from the "ecdsa" example of the SDK
//**************************************//
#include "app_error.h"
#include "nrf_assert.h"
#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_ecdsa.h"
#include "nrf_crypto_error.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "sdk_common.h"
//**************************************//

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

#include <uECC.h>

#define ECDSA_WITH_SHA256_SECP_256_ASN_ENCODED_SIGNATURE_SIZE 80

enum {
  ASN1_SEQUENCE = 0x30,
  ASN1_INTEGER = 0x02,
};

/** \brief Determine ASN1 length of integer at integer[0:20].
    */
int determineAsn1IntLength(const uint8_t *integer, uECC_Curve curve);

uint8_t *
writeAsn1Int(uint8_t *output, const uint8_t *integer, int length, uECC_Curve curve);

/** \brief Encode x-octet raw signature at sig[8:x+8] as DER at sig[0:retval].
    */
bool encodeSignatureBits(uint8_t *sig, uint16_t *sigLength, uECC_Curve curve);

/** \brief Will generate an ECC key pair for you using uECC. If the lengths of the buffers you pass
    in are not long enough, will return false. If successful, the size of the generated keys will be
    the same as uECC_curve_private_key_size(curve) and uECC_curve_public_key_size(curve)
    */
int sign_on_basic_nrf_crypto_gen_ec_keypair(uint8_t *pub_key_buf, uint16_t pub_key_buf_len, uint16_t *pub_key_output_len,
    uint8_t *pri_key_buf, uint16_t pri_key_buf_len, uint16_t *pri_key_output_len,
    uECC_Curve curve);

/** \brief Outputs an ASN1 formatted ECDSA signature over the given payload with the specified curve
    */
int sign_on_basic_nrf_crypto_gen_sha256_ecdsa_sig(
    const uint8_t *pri_key_raw, uECC_Curve curve,
    const uint8_t *payload, uint16_t payload_len,
    uint8_t *output_buf, uint16_t output_buf_len, uint16_t *output_len);

int sign_on_basic_nrf_crypto_gen_ecdh_shared_secret(
    const uint8_t *pub_key_raw, uint16_t pub_key_raw_len,
    const uint8_t *pri_key_raw, uint16_t pri_key_raw_len,
    uECC_Curve curve,
    uint8_t *output_buf, uint16_t output_buf_len, uint16_t *output_len);

#endif // ECC_NRF_CRYPTO_IMPL_H