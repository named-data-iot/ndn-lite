
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