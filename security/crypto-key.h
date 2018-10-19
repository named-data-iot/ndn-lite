#ifndef NDN_SECURITY_CRYPTO_KEY_H
#define NDN_SECURITY_CRYPTO_KEY_H

#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_ecdsa {
    uint32_t type;
    uint8_t pub[64];
    uint8_t pvt[32];
} ndn_ecdsa_t;

typedef struct ndn_hmac {
    uint32_t size;
    uint8_t keydata[NDN_SIGNATURE_BUFFER_SIZE];
} ndn_hmac_t;

static inline int
ndn_ecdsa_set_public_key(ndn_ecdsa_t* pair, ndn_buffer_t* keydata)
{
  if(keydata->size < 64)
    return NDN_ERROR_OVERSIZE;
  memcpy(pair->pub, keydata->value, 64);
  return 0;
}

static inline int
ndn_ecdsa_set_private_key(ndn_ecdsa_t* pair, ndn_buffer_t* keydata)
{
  if(keydata->size < 32)
    return NDN_ERROR_OVERSIZE;
  memcpy(pair->pvt, keydata->value, 32);
  return 0;
}

static inline int
ndn_ecdsa_set_type(ndn_ecdsa_t* pair, uint32_t ecdsa_type)
{
  if(ecdsa_type != NDN_ECDSA_CURVE_SECP160R1 &&
     ecdsa_type != NDN_ECDSA_CURVE_SECP192R1 &&
     ecdsa_type != NDN_ECDSA_CURVE_SECP224R1 &&
     ecdsa_type != NDN_ECDSA_CURVE_SECP256R1 &&
     ecdsa_type != NDN_ECDSA_CURVE_SECP256K1 )
     return -1;
  pair->type = ecdsa_type;
  return 0;
}

static inline int
ndn_hmac_set_key(ndn_hmac_t* key, ndn_buffer_t* data)
{
  if(data->size > NDN_SIGNATURE_BUFFER_SIZE)
    return NDN_ERROR_OVERSIZE;
  key->size = data->size;
  memcpy(key->keydata, data->value, data->size);
  return 0;
}

#ifdef __cplusplus
}
#endif

#endif // NDN_SECURITY_CRYPTO_KEY_H
