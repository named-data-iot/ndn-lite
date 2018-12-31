
#ifndef NDN_LITE_AES_TINYCRIPT_IMPL_H
#define NDN_LITE_AES_TINYCRIPT_IMPL_H

#include <stdint.h>

int ndn_lite_aes_cbc_encrypt_tinycript(const uint8_t* input_value, uint8_t input_size,
                                       uint8_t* output_value, uint8_t output_size,
                                       const uint8_t* aes_iv,
                                       const uint8_t* key_value, uint8_t key_size);

int ndn_lite_aes_cbc_decrypt_tinycript(const uint8_t* input_value, uint8_t input_size,
                                       uint8_t* output_value, uint8_t output_size,
                                       const uint8_t* aes_iv,
                                       const uint8_t* key_value, uint8_t key_size);

#endif // NDN_LITE_AES_TINYCRIPT_IMPL_H