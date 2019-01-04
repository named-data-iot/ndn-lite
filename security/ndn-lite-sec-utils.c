
#include "ndn-lite-sec-utils.h"

#include <stddef.h>

#include "../ndn-error-code.h"

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

// the below utility functions for asn encoding a micro-ecc generated ecdsa signature
// adapted from: 
// https://github.com/yoursunny/esp8266ndn/blob/master/src/security/detail/ec-impl-microecc.hpp

int determineAsn1IntLength(const uint8_t *integer, uECC_Curve curve) {

  int priKeySize = uECC_curve_private_key_size(curve);

  // if the top bit of the first integer is 1, then an extra 0 byte needs to be added
  // to keep the integer positive since it is encoded in two's complement
  if ((integer[0] & 0x80) != 0x00) {
    return priKeySize + 1;
  }

  // if the top bit of the first integer is 0, then still need to check if there are more
  // zero bytes that can be cut off, since the ASN.1 encoding of a r and s ECDSA signature pair
  // requires that r and s be represented a minimal amount of bytes possible
  int len = priKeySize;
  for (int i = 0; i < priKeySize - 1; ++i) {
    if (((integer[i] << 8) | (integer[i + 1] & 0x80)) != 0x0000) {
      break;
    }
    --len;
  }
  return len;
}

uint8_t *
writeAsn1Int(uint8_t *output, const uint8_t *integer, int length, uECC_Curve curve) {
  *(output++) = ASN1_INTEGER;
  *(output++) = (uint8_t)(length);

  int priKeySize = uECC_curve_private_key_size(curve);

  if (length == priKeySize + 1) {
    *(output++) = 0x00;
    memmove(output, integer, priKeySize);
    return output + priKeySize;
  }

  memmove(output, integer + priKeySize - length, length);
  return output + length;
}

bool encodeSignatureBits(uint8_t *sig, uint32_t *sigLength, uECC_Curve curve) {
  memmove(sig + 8, sig, 64);
  const uint8_t *begin = sig;
  const uint8_t *r = sig + 8;
  const uint8_t *s = r + uECC_curve_private_key_size(curve);
  int rLength = determineAsn1IntLength(r, curve);
  int sLength = determineAsn1IntLength(s, curve);

  *(sig++) = ASN1_SEQUENCE;
  *(sig++) = 2 + rLength + 2 + sLength;
  sig = writeAsn1Int(sig, r, rLength, curve);
  sig = writeAsn1Int(sig, s, sLength, curve);

  *sigLength = sig - begin;

  return true;
}