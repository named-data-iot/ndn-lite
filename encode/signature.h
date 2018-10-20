#ifndef NDN_ENCODING_SIGNATURE_H
#define NDN_ENCODING_SIGNATURE_H

#include "name.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_validaty_period {
  uint8_t not_before[15];
  uint8_t not_after[15];
} ndn_validity_period_t;

// we don't support key digest as KeyLocator in NDN IoT
typedef struct ndn_signature {
  uint8_t sig_type;
  uint8_t sig_value[NDN_SIGNATURE_BUFFER_SIZE];
  uint32_t sig_size;

  uint8_t enable_KeyLocator;
  uint8_t enable_ValidityPeriod;

  ndn_name_t key_locator_name;
  ndn_validity_period_t validity_period;

} ndn_signature_t;

// set signature type, signature size, and disable keylocator and validity period by default
static inline int
ndn_signature_init(ndn_signature_t* signature, uint8_t type)
{
  switch (type) {
  case NDN_SIG_TYPE_DIGEST_SHA256:
    signature->sig_size = 32;
    break;
  case NDN_SIG_TYPE_ECDSA_SHA256:
    signature->sig_size = 64;
    break;
  case NDN_SIG_TYPE_HMAC_SHA256:
    signature->sig_size = 32;
    break;
  default:
    return NDN_ERROR_UNSUPPORT_SIGN_TYPE;
  }
  signature->enable_KeyLocator = 0;
  signature->enable_ValidityPeriod = 0;
  signature->sig_type = type;
  return 0;
}

// will do memory copy
static inline int
ndn_signature_set_signature(ndn_signature_t* signature, const uint8_t* sig_value, size_t sig_size)
{
  if (sig_size > NDN_SIGNATURE_BUFFER_SIZE)
    return NDN_ERROR_OVERSIZE;

  if (signature->sig_type == NDN_SIG_TYPE_ECDSA_SHA256 && sig_size != 64)
    return NDN_ERROR_WRONG_SIG_SIZE;

  if (signature->sig_type == NDN_SIG_TYPE_HMAC_SHA256 && sig_size != 32)
    return NDN_ERROR_WRONG_SIG_SIZE;

  if (signature->sig_type == NDN_SIG_TYPE_DIGEST_SHA256 && sig_size != 32)
    return NDN_ERROR_WRONG_SIG_SIZE;

  signature->sig_size = sig_size;
  memcpy(signature->sig_value, sig_value, sig_size);
  return 0;
}

// will do memory copy
// This function is NOT recommended.
// Better to first init signature and init signature.keylocator_name and set enable_KeyLocator = 1
static inline void
ndn_signature_set_key_locator(ndn_signature_t* signature, const ndn_name_t* key_name)
{
  signature->enable_KeyLocator = 1;
  memcpy(&signature->key_locator_name, key_name, sizeof(ndn_name_t));
}

// not before and not after must be ISO 8601 time format, which is 15 bytes long
static inline void
ndn_signature_set_validity_period(ndn_signature_t* signature,
                                  const uint8_t* not_before, const uint8_t* not_after)
{
  signature->enable_ValidityPeriod = 1;
  memcpy(signature->validity_period.not_before, not_before, 15);
  memcpy(signature->validity_period.not_after, not_after, 15);
}

static inline uint32_t
ndn_signature_info_probe_block_size(const ndn_signature_t* signature)
{
  // signature type
  uint32_t info_buffer_size = encoder_probe_block_size(TLV_SignatureType, 1);

  if (signature->enable_KeyLocator) {
    uint32_t key_name_block_size = ndn_name_probe_block_size(&signature->key_locator_name);
    info_buffer_size += encoder_probe_block_size(TLV_KeyLocator, key_name_block_size);
  }
  if (signature->enable_ValidityPeriod) {
    uint32_t validity_period_buffer_size = encoder_probe_block_size(TLV_NotBefore, 15);
    validity_period_buffer_size += encoder_probe_block_size(TLV_NotAfter, 15);
    info_buffer_size += encoder_probe_block_size(TLV_ValidityPeriod, validity_period_buffer_size);
  }
  return encoder_probe_block_size(TLV_SignatureInfo, info_buffer_size);
}

static inline uint32_t
ndn_signature_value_probe_block_size(const ndn_signature_t* signature)
{
  return encoder_probe_block_size(TLV_SignatureValue, signature->sig_size);
}

int
ndn_signature_info_tlv_encode(ndn_encoder_t* encoder, const ndn_signature_t* signature);

int
ndn_signature_value_tlv_encode(ndn_encoder_t* encoder, const ndn_signature_t* signature);

int
ndn_signature_info_tlv_decode(ndn_decoder_t* decoder, ndn_signature_t* signature);

int
ndn_signature_value_tlv_decode(ndn_decoder_t* decoder, ndn_signature_t* signature);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_SIGNATURE_H
