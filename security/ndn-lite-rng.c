
#include "ndn-lite-rng.h"
#include "ndn-lite-sec-config.h"

int ndn_lite_rng(uint8_t *dest, unsigned size) {
#ifdef NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO
  return ndn_lite_nrf_crypto_rng(dest, size);
#endif
}