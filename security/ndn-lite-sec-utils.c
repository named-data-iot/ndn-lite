/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn-lite-sec-utils.h"
#include <stddef.h>
#include <string.h>
#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include "../ndn-enums.h"

#include "../adaptation/ndn-nrf-ble-adaptation/logger.h"

int
ndn_const_time_memcmp(const uint8_t* a, const uint8_t* b, uint32_t size)
{
  unsigned char result = 0; /* will be 0 if equal, nonzero otherwise */
  for (size_t i = 0; i < size; i++) {
    result |= a[i] ^ b[i];
  }
  if (result == 0)
    return NDN_SUCCESS;
  return NDN_SEC_CRYPTO_ALGO_FAILURE;
}

/**
 * Get the length that an integer value will have if encoded
 * in ASN.1 DER format. Does not include tlv type or length fields.
 * @return Length of ASN.1 DER encoding of integer if there is no error,
 *           -1 if there is an error.
 */
int
_probe_integer_asn1_encoded_size(uint8_t *val, uint32_t val_len) {
  if (val_len < 0) {
    return -1;
  }
  if (val_len == 0) {
    return 0;
  }
  if ((val[0] & 0x80) != 0x00) {
    return val_len + 1;
  }
  return val_len;
}

/**
 * Write an integer in ASN.1 format. Assumes that the output buffer is long
 *   enough to hold the ASN.1 integer tlv type, tlv length, and the value
 *   of the integer (plus the extra 0 padding bit if the integer started with
 *   a 1 bit).
 * The original value and the destination can overlap.
 * @return 0 if there is no error, -1 if there is an error.
 */
int
_write_asn1_integer(uint8_t *val, uint32_t val_len, uint8_t *output) {
  uint32_t encoded_int_size = _probe_integer_asn1_encoded_size(val, val_len);
  if (encoded_int_size  == -1) {
    return -1;
  }
  if (encoded_int_size > val_len) {
    memmove(output + 3, val, val_len);
    *(output + 2) = 0;
  }
  else {
    memmove(output + 2, val, val_len);
  }
  *output = ASN1_INTEGER;
  *(output+1) = encoded_int_size;
  return 0;
}

int
ndn_asn1_probe_ecdsa_signature_encoding_size(uint8_t *raw_ecdsa_sig, uint32_t raw_ecdsa_sig_len, 
                                             uint32_t *encoded_ecdsa_sig_len) {

  if (raw_ecdsa_sig_len < NDN_ASN1_ECDSA_MIN_RAW_SIG_SIZE) {
    return NDN_ASN_ENCODE_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len % 2 != 0) {
    return NDN_ASN_ENCODE_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len == 0) {
    return 0;
  }

  uint32_t sig_int_size = raw_ecdsa_sig_len / 2;
  uint32_t r_encoded_len = _probe_integer_asn1_encoded_size(raw_ecdsa_sig, sig_int_size);
  if (r_encoded_len == -1) {
    return NDN_ASN_ENCODE_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
  }
  uint32_t s_encoded_len = _probe_integer_asn1_encoded_size(raw_ecdsa_sig + sig_int_size, sig_int_size);
  if (s_encoded_len == -1) {
    return NDN_ASN_ENCODE_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
  }

  uint32_t encoded_sig_size = 2 + // ASN1.SEQUENCE tlv type and length fields size
                              2 + // ASN1.INTEGER tlv type and length fields size
                              r_encoded_len +
                              2 + // ASN1.INTEGER tlv type and length fields size
                              s_encoded_len;

  *encoded_ecdsa_sig_len = encoded_sig_size;
  return NDN_SUCCESS;
}

int
ndn_asn1_encode_ecdsa_signature(uint8_t* sig_buf, uint32_t raw_ecdsa_sig_len, 
                                uint32_t sig_buf_len) {

  if (raw_ecdsa_sig_len < NDN_ASN1_ECDSA_MIN_RAW_SIG_SIZE || sig_buf_len < NDN_ASN1_ECDSA_MIN_RAW_SIG_SIZE) {
    return NDN_ASN_ENCODE_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len % 2 != 0) {
    return NDN_ASN_ENCODE_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len == 0) {
    return 0;
  }

  uint32_t sig_int_size = raw_ecdsa_sig_len / 2;
  uint32_t r_encoded_len = _probe_integer_asn1_encoded_size(sig_buf, sig_int_size);
  if (r_encoded_len == -1) {
    return NDN_ASN_ENCODE_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
  }
  uint32_t s_encoded_len = _probe_integer_asn1_encoded_size(sig_buf + sig_int_size, sig_int_size);
  if (s_encoded_len == -1) {
    return NDN_ASN_ENCODE_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
  }

  APP_LOG("r_encoded_len: %d\n", r_encoded_len);
  APP_LOG("s_encoded_len: %d\n", s_encoded_len);

  uint32_t encoded_sig_size = 2 + // ASN1.SEQUENCE tlv type and length fields size
                              2 + // ASN1.INTEGER tlv type and length fields size
                              r_encoded_len +
                              2 + // ASN1.INTEGER tlv type and length fields size
                              s_encoded_len;

  if (encoded_sig_size > sig_buf_len) {
    return NDN_ASN_ENCODE_ECDSA_SIG_BUFFER_TOO_SMALL;
  }

  APP_LOG_HEX("Value of sig buf before any operations:", sig_buf, sig_buf_len);

  memmove(sig_buf + 2 + 2, sig_buf, raw_ecdsa_sig_len);

  APP_LOG_HEX("Value of sig buf after moving raw signature up 4 bytes:", sig_buf, sig_buf_len);

  // add ASN1.SEQUENCE tlv type and length
  *sig_buf = ASN1_SEQUENCE;
  *(sig_buf + 1) = (uint8_t)(encoded_sig_size - 2);

  APP_LOG_HEX("Value of sig buf after writing ASN1.SEQUENCE tlv type and length:", sig_buf, sig_buf_len);
  
  // add s integer (do s first so that r's value isn't overwritten)
  uint32_t s_offset = 2 + 2 + sig_int_size;
  uint32_t s_final_encoding_offset = 2 + 2 + r_encoded_len;
  if (_write_asn1_integer(sig_buf + s_offset,
                      sig_int_size,
                      sig_buf + s_final_encoding_offset) == -1) {
    return NDN_ASN_ENCODE_ECDSA_SIG_FAILED_TO_WRITE_ASN1_INT;
  }

  APP_LOG_HEX("Value of sig buf after writing ASN1 encoded s:", sig_buf, sig_buf_len);
  
  // add r integer
  uint32_t r_offset = 2 + 2;
  uint32_t r_final_encoding_offset = 2;
  if (_write_asn1_integer(sig_buf + r_offset,
                      sig_int_size,
                      sig_buf + r_final_encoding_offset) == -1) {
    return NDN_ASN_ENCODE_ECDSA_SIG_FAILED_TO_WRITE_ASN1_INT;
  }

  APP_LOG_HEX("Value of sig buf after writing ASN1 encoded r:", sig_buf, sig_buf_len);

  return NDN_SUCCESS;
}