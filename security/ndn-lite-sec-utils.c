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

/** @brief Determine ASN1 length of integer at integer[0:32]. */
static int
determineAsn1IntLength(const uint8_t* integer)
{
  if ((integer[0] & 0x80) != 0x00) {
    return 33;
  }

  int len = 32;
  for (int i = 0; i < 31; ++i) {
    if ((((uint16_t)(integer[i]) << 8) | (integer[i + 1] & 0x80)) != 0x0000) {
      break;
    }
    --len;
  }
  return len;
}

/** @brief Write ASN1 integer from integer[0:32] to output..retval; buffers may overlap. */
static uint8_t*
writeAsn1Int(uint8_t* output, const uint8_t* integer, int length)
{
  *(output++) = ASN1_INTEGER;
  *(output++) = (uint8_t)(length);

  if (length == 33) {
    *(output++) = 0x00;
    memmove(output, integer, 32);
    return output + 32;
  }

  memmove(output, integer + 32 - length, length);
  return output + length;
}

/** @brief Encode 64-octet raw signature at sig[8:72] as DER at sig[0:retval]. */
static int
encodeSignatureBits(uint8_t* sig)
{
  const uint8_t* begin = sig;
  const uint8_t* r = sig + 8;
  const uint8_t* s = r + 32;
  int rLength = determineAsn1IntLength(r);
  int sLength = determineAsn1IntLength(s);

  *(sig++) = ASN1_SEQUENCE;
  *(sig++) = 2 + rLength + 2 + sLength;
  sig = writeAsn1Int(sig, r, rLength);
  sig = writeAsn1Int(sig, s, sLength);

  return sig - begin;
}

/**
 * @brief Read ASN1 integer at input..end into output[0:32].
 * @return pointer past end of ASN1 integer, or NULL if failure.
 */
static const uint8_t*
readAsn1Int(const uint8_t* input, const uint8_t* end, uint8_t* output)
{
  if (input == end || *(input++) != ASN1_INTEGER)
    return NULL;

  uint8_t length = (input == end) ? 0 : *(input++);
  if (length == 0 || input + length > end)
    return NULL;

  if (length == 33) {
    --length;
    ++input;
  }
  memcpy(output + 32 - length, input, length);
  return input + length;
}

/** @brief Decode DER-encoded ECDSA signature into 64-octet raw signature. */
static bool
decodeSignatureBits(const uint8_t* input, size_t len, uint8_t* decoded)
{
  memset(decoded, 0, NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE);
  const uint8_t* end = input + len;

  if (input == end || *(input++) != ASN1_SEQUENCE)
    return false;
  if (input == end)
    return false;
  uint8_t seqLength = *(input++);
  if (input + seqLength != end)
    return false;

  input = readAsn1Int(input, end, decoded + 0);
  input = readAsn1Int(input, end, decoded + 32);
  return input == end;
}

int
ndn_asn1_probe_ecdsa_signature_encoding_size(const uint8_t *raw_ecdsa_sig, uint32_t raw_ecdsa_sig_len,
                                             uint32_t *encoded_ecdsa_sig_len)
{
  if (raw_ecdsa_sig_len != 64) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }
  uint8_t sig[72];
  memcpy(&sig[8], raw_ecdsa_sig, 64);
  *encoded_ecdsa_sig_len = (uint32_t)encodeSignatureBits(sig);
  return NDN_SUCCESS;
}

int
ndn_asn1_encode_ecdsa_signature(uint8_t* sig_buf, uint32_t raw_ecdsa_sig_len,
                                uint32_t sig_buf_len)
{
  if (raw_ecdsa_sig_len != 64) {
    return NDN_ASN1_ECDSA_SIG_INVALID_SIZE;
  }
  uint8_t sig[72];
  memcpy(&sig[8], sig_buf, 64);
  int sigLen = encodeSignatureBits(sig);
  if (sigLen > (int)sig_buf_len) {
    return NDN_ASN1_ECDSA_SIG_BUFFER_TOO_SMALL;
  }
  memcpy(sig_buf, sig, sigLen);
  return NDN_SUCCESS;
}

int
ndn_asn1_decode_ecdsa_signature(const uint8_t *encoded_ecdsa_sig, uint32_t encoded_ecdsa_sig_len,
                                uint8_t *decoded_ecdsa_sig, uint32_t decoded_ecdsa_sig_buf_len,
                                uint32_t *raw_ecdsa_sig_len)
{
  if (decoded_ecdsa_sig_buf_len < NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE) {
    return NDN_ASN1_ECDSA_SIG_BUFFER_TOO_SMALL;
  }
  *raw_ecdsa_sig_len = NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE;

  bool ok = decodeSignatureBits(encoded_ecdsa_sig, encoded_ecdsa_sig_len, decoded_ecdsa_sig);
  return ok ? NDN_SUCCESS : NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_INT;
}
