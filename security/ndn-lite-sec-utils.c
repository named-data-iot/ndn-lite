/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-lite-sec-utils.h"
#include <stddef.h>
#include <string.h>
#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include "../ndn-enums.h"

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
 * Get the length that a raw integer value will have if encoded
 * in ASN.1 DER format. Does not include tlv type or length fields.
 * @return Length of ASN.1 DER encoding of integer if there is no error,
 *           -1 if there is an error.
 */
int
_probe_raw_integer_asn1_encoded_size(const uint8_t *val, uint32_t val_len)
{
  if (val_len <= 0) {
    return 0;
  }
  if ((val[0] & 0x80) != 0x00) {
    return val_len + 1;
  }
  return val_len;
}

/**
 * Get the length that an ASN.1 encoded integer value will have if the
 * raw value is extracted. This means that asn1 integer tlv type and length,
 * as well as any padding bytes, are excluded.
 * @param val. Input. This is the pointer to the ASN.1 encoded integer. Note that
 *                      this is a pointer to the integer within the ASN.1 integer tlv block,
 *                      not to the ASN.1 tlv block tlv type.
 * @param val_len. Input. This is the tlv length of the ASN1. integer tlv block.
 * @return Length of raw integer if there is no error,
 *           -1 if there is an error.
 */
int
_probe_asn1_encoded_integer_raw_size(const uint8_t *val, uint32_t val_len)
{
  if (val_len <= 0) {
    return -1;
  }
  if (val[0] == 0x00) {
    if ((val[1] & 0x80) != 0x00) {
      return val_len - 1;
    }
    else {
      return val_len;
    }
  }
  else {
    return val_len;
  }
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
_write_asn1_integer(const uint8_t *val, uint32_t val_len, uint8_t *output)
{
  int encoded_int_size = _probe_raw_integer_asn1_encoded_size(val, val_len);
  if (encoded_int_size == -1) {
    return -1;
  }
  if ((uint32_t)encoded_int_size > val_len) {
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

/**
 * Read an integer in ASN.1 format. Assumes that the output buffer is long
 *   enough to hold the raw integer (without the possible zero padding byte).
 * @return Length of raw integer if there is no error, -1 if there is an error.
 */
int
_read_asn1_integer(const uint8_t *asn1_int, uint32_t asn1_int_len, uint8_t *output)
{
  if (asn1_int[0] != ASN1_INTEGER) {
    return -1;
  }

  uint32_t asn1_int_tlv_val_len = (uint32_t) asn1_int[1];
  if (asn1_int_tlv_val_len != asn1_int_len - 2) {
    return -1;
  }

  if (asn1_int[2] == 0) {
    // check whether the zero byte is a padding zero byte or part of the actual raw integer
    if ((asn1_int[3] & 0x80) != 0x00) {
      // this means the zero byte was used for padding, so skip it and just copy the integer
      memcpy(output, asn1_int + 3, asn1_int_tlv_val_len - 1);
      return asn1_int_tlv_val_len - 1;
    }
    else {
      // this means the zero byte wasn't used for padding, copy it as part of the integer
      memcpy(output, asn1_int + 2, asn1_int_tlv_val_len);
      return asn1_int_tlv_val_len;
    }
  }
  else {
    memcpy(output, asn1_int + 2, asn1_int_tlv_val_len);
    return asn1_int_tlv_val_len;
  }
}

int
ndn_asn1_probe_ecdsa_signature_encoding_size(const uint8_t *raw_ecdsa_sig, uint32_t raw_ecdsa_sig_len,
                                             uint32_t *encoded_ecdsa_sig_len)
{
  if (raw_ecdsa_sig_len < NDN_ASN1_ECDSA_MIN_RAW_SIG_SIZE) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len % 2 != 0) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len == 0) {
    return 0;
  }

  int sig_int_size = raw_ecdsa_sig_len / 2;
  int r_encoded_len = _probe_raw_integer_asn1_encoded_size(raw_ecdsa_sig, sig_int_size);
  if (r_encoded_len == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
  }
  int s_encoded_len = _probe_raw_integer_asn1_encoded_size(raw_ecdsa_sig + sig_int_size, sig_int_size);
  if (s_encoded_len == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
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
                                uint32_t sig_buf_len)
{
  if (raw_ecdsa_sig_len < NDN_ASN1_ECDSA_MIN_RAW_SIG_SIZE ||
      sig_buf_len < NDN_ASN1_ECDSA_MIN_RAW_SIG_SIZE) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len % 2 != 0) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }

  if (raw_ecdsa_sig_len == 0) {
    return 0;
  }

  uint32_t sig_int_size = raw_ecdsa_sig_len / 2;
  int r_encoded_len = _probe_raw_integer_asn1_encoded_size(sig_buf, sig_int_size);
  if (r_encoded_len == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
  }
  int s_encoded_len = _probe_raw_integer_asn1_encoded_size(sig_buf + sig_int_size, sig_int_size);
  if (s_encoded_len == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE;
  }

  uint32_t encoded_sig_size = 2 + // ASN1.SEQUENCE tlv type and length fields size
    2 + // ASN1.INTEGER tlv type and length fields size
    r_encoded_len +
    2 + // ASN1.INTEGER tlv type and length fields size
    s_encoded_len;

  if (encoded_sig_size > sig_buf_len) {
    return NDN_ASN1_ECDSA_SIG_BUFFER_TOO_SMALL;
  }

  memmove(sig_buf + 2 + 2, sig_buf, raw_ecdsa_sig_len);

  // add ASN1.SEQUENCE tlv type and length
  *sig_buf = ASN1_SEQUENCE;
  *(sig_buf + 1) = (uint8_t)(encoded_sig_size - 2);

  // add s integer (do s first so that r's value isn't overwritten)
  uint32_t s_offset = 2 + 2 + sig_int_size;
  uint32_t s_final_encoding_offset = 2 + 2 + r_encoded_len;
  if (_write_asn1_integer(sig_buf + s_offset,
                          sig_int_size,
                          sig_buf + s_final_encoding_offset) == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_WRITE_ASN1_INT;
  }

  // add r integer
  uint32_t r_offset = 2 + 2;
  uint32_t r_final_encoding_offset = 2;
  if (_write_asn1_integer(sig_buf + r_offset,
                          sig_int_size,
                          sig_buf + r_final_encoding_offset) == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_WRITE_ASN1_INT;
  }

  return NDN_SUCCESS;
}

int
ndn_asn1_decode_ecdsa_signature(const uint8_t *encoded_ecdsa_sig, uint32_t encoded_ecdsa_sig_len,
                                uint8_t *decoded_ecdsa_sig, uint32_t decoded_ecdsa_sig_buf_len,
                                uint32_t *raw_ecdsa_sig_len)
{
  if (encoded_ecdsa_sig_len < NDN_ASN1_ECDSA_MIN_ENCODED_SIG_SIZE) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }
  if (encoded_ecdsa_sig_len > NDN_ASN1_ECDSA_MAX_ENCODED_SIG_SIZE) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }

  if (encoded_ecdsa_sig[0] != ASN1_SEQUENCE) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_SEQUENCE;
  }

  uint32_t r_tlv_block_offset = 2;
  uint32_t r_tlv_block_val_len = (uint32_t) (*(encoded_ecdsa_sig + r_tlv_block_offset + 1));
  int r_raw_len = _probe_asn1_encoded_integer_raw_size(encoded_ecdsa_sig + r_tlv_block_offset + 2,
                                                       r_tlv_block_val_len);
  if (r_raw_len == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_INT;
  }

  uint32_t s_tlv_block_offset = r_tlv_block_offset + 2 + r_tlv_block_val_len;
  uint32_t s_tlv_block_val_len = (uint32_t)(*(encoded_ecdsa_sig + r_tlv_block_offset + 2 + r_tlv_block_val_len + 1));
  int s_raw_len = _probe_asn1_encoded_integer_raw_size(encoded_ecdsa_sig + s_tlv_block_offset + 2,
                                                       s_tlv_block_val_len);
  if (s_raw_len == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_INT;
  }

  if (encoded_ecdsa_sig_len != 2 + 2 + r_tlv_block_val_len + 2 + s_tlv_block_val_len) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }

  if (decoded_ecdsa_sig_buf_len < (uint32_t)(r_raw_len + s_raw_len)) {
    return NDN_ASN1_ECDSA_SIG_BUFFER_TOO_SMALL;
  }

  int ret;
  ret = _read_asn1_integer(encoded_ecdsa_sig + r_tlv_block_offset, 2 + r_tlv_block_val_len, decoded_ecdsa_sig);
  if (ret == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_INT;
  }
  ret = _read_asn1_integer(encoded_ecdsa_sig + s_tlv_block_offset,
                           2 + s_tlv_block_val_len, decoded_ecdsa_sig + r_raw_len);
  if (ret == -1) {
    return NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_INT;
  }

  *raw_ecdsa_sig_len = r_raw_len + s_raw_len;
  return NDN_SUCCESS;
}
