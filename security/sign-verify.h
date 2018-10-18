#ifndef NDN_SECURITY_SIGN_VERIFY_H_
#define NDN_SECURITY_SIGN_VERIFY_H_

#include "key-types.h"

#ifdef __cplusplus
extern "C" {
#endif

int
security_sign_block(const ndn_block_t* input, const uint8_t* key_data, ndn_buffer_t* output,
                    uint32_t key_size, uint32_t type, uint32_t ecdsa_type);

int
security_verify_block(const ndn_block_t* input, const uint8_t* key_data, const ndn_buffer_t* value,
                      uint32_t key_size, uint32_t type, uint32_t ecdsa_type);

static inline int
ndn_security_ecdsa_sign_block(const ndn_block_t* input, const ndn_ecdsa_t* key, ndn_buffer_t* output)
{
  return security_sign_block(input, key->pvt, output, 32,
                             NDN_SIG_TYPE_ECDSA_SHA256, key->type);
}

static inline int
ndn_security_ecdsa_verify_block(const ndn_block_t* input, const ndn_ecdsa_t* key, const ndn_buffer_t* value)
{
  return security_verify_block(input, key->pub, value, 64,
                               NDN_SIG_TYPE_ECDSA_SHA256, key->type);
}

static inline int
ndn_security_hmac_sign_block(const ndn_block_t* input, const ndn_hmac_t* key, ndn_buffer_t* output)
{
  return security_sign_block(input, key->keydata, output, key->size,
                             NDN_SIG_TYPE_HMAC_SHA256, 0);
}

static inline int
ndn_security_hmac_verify_block(const ndn_block_t* input, const ndn_hmac_t* key, const ndn_buffer_t* value)
{
  return security_verify_block(input, key->keydata, value, key->size,
                               NDN_SIG_TYPE_HMAC_SHA256, 0);
}

static inline int
ndn_security_digest_sign_block(const ndn_block_t* input, ndn_buffer_t* output)
{
  return security_sign_block(input, NULL, output, 0,
                             NDN_SIG_TYPE_DIGEST_SHA256, 0);
}

static inline int
ndn_security_digest_verify_block(const ndn_block_t* input, const ndn_buffer_t* value)
{
  return security_verify_block(input, NULL, value, 0,
                               NDN_SIG_TYPE_DIGEST_SHA256, 0);
}

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_SIGN_VERIFY_H_
