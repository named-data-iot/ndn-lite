

#include "../ndn-lite-sec-config.h"

#ifdef NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO

#include "../random.h"
#include "nrf_crypto.h"
#include "../sign-verify.h"

int
ndn_random_hkdf(const uint8_t* input_value, uint32_t input_size,
                uint8_t* output_value, uint32_t output_size,
                const uint8_t* seed_value, uint32_t seed_size)
{
  uint8_t prk[32] = {0};
  uint32_t used_bytes = 0;
  ndn_signer_hmac_sign(input_value, input_size, prk, 32, seed_value, seed_size, &used_bytes);

  int iter;
  if (output_size % 32)
    iter = output_size / 32 + 1;
  else
    iter = output_size / 32;
  uint8_t t[32] = {0};
  uint8_t cat[33] = {0};
  uint8_t okm[32 * iter];
  for (uint8_t i = 0; i < 32 * iter; i++)
    okm[i] = 0;
  uint8_t table[16] = {0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  uint8_t t_first[2] = {0x00, 0x01};
  for (int i = 0; i < iter; ++i) {
    if (i == 0) {
      ndn_signer_hmac_sign(t_first, sizeof(t_first), t, 32, prk, 32, &used_bytes);
      memcpy(okm + i * 32, t, 32);
    }
    else {
      memcpy(cat, t, 32);
      cat[32] = table[i];
      ndn_signer_hmac_sign(cat, 33, t, 32, prk, 32, &used_bytes);
      memcpy(okm + i * 32, t, 32);
    }
  }
  memcpy(output_value, okm, output_size);
  return 0;
}

// for this to work properly, should have proper flags set in sdk_config.h,
// as is outlined in RNG Usage section of this resource:
// https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v15.0.0%2Flib_crypto_rng.html

int
ndn_random_hmacprng(const uint8_t* input_value, uint32_t input_size,
                    uint8_t* output_value, uint32_t output_size,
                    const uint8_t* seed_value, uint32_t seed_size,
                    const uint8_t* additional_value, uint32_t additional_size)
{
  nrf_crypto_init();
  nrf_crypto_rng_temp_buffer_t temp_reseed_buffer;
  size_t seed_len = (size_t) seed_size;
  nrf_crypto_rng_reseed(&temp_reseed_buffer, seed_value, seed_len);
  size_t output_len = (size_t) output_size;
  nrf_crypto_rng_vector_generate(output_value, output_len);
  return 0;
}

#endif // NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO