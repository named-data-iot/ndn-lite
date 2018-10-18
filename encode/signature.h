#ifndef ENCODING_SIGNATURE_H
#define ENCODING_SIGNATURE_H

#include "name.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_keylocator{
  uint32_t type;
  ndn_buffer_t keydigest;
  ndn_name_t keyname;
} ndn_keylocator_t;

typedef struct ndn_validityperiod {
  uint32_t notbefore;
  uint32_t notafter;
} ndn_validityperiod_t;


typedef struct ndn_signature {
  uint32_t type;
  ndn_buffer_t signature_value;
  ndn_buffer_t signature_info;

  uint8_t enable_keylocator;
  uint8_t enable_keydigest;

  uint8_t value_holder[NDN_SIGNATURE_BUFFER_SIZE];
  uint8_t keylocator_holder[NDN_SIGNATURE_BUFFER_SIZE];

  ndn_keylocator_t keylocator;
  ndn_validityperiod_t validityperiod;
} ndn_signature_t;

static inline int
ndn_signature_init(ndn_signature_t* signature, uint32_t type){
  if(type != NDN_SIG_TYPE_DIGEST_SHA256 && type != NDN_SIG_TYPE_ECDSA_SHA256 &&
     type != NDN_SIG_TYPE_HMAC_SHA256 && type != NDN_SIG_TYPE_RSA_SHA256)
  return -1;

  switch(type){
    case NDN_SIG_TYPE_DIGEST_SHA256:
        signature->signature_value.size = 32;
        break;

    case NDN_SIG_TYPE_ECDSA_SHA256:
        signature->signature_value.size = 64;
        break;

    case NDN_SIG_TYPE_HMAC_SHA256:
        signature->signature_value.size = 32;
        break;

    case NDN_SIG_TYPE_RSA_SHA256:
        signature->signature_value.size = 124;
        break;
  }

  signature->enable_keylocator = 0;
  signature->enable_keydigest = 0;
  signature->signature_value.value = signature->value_holder;
  signature->type = type;
  return 0;
}

// will do memory copy
static inline void
ndn_signature_set_signataure_value(ndn_signature_t* signature, ndn_buffer_t* input){
  signature->signature_value.size = input->size;
  memcpy(signature->signature_value.value, input->value, input->size);
}

static inline void
ndn_signature_enable_keylocator(ndn_signature_t* signature){
  signature->enable_keylocator = 1;
}

static inline void
ndn_signature_enable_keylocator_keydigest(ndn_signature_t* signature){
  signature->enable_keydigest = 1;
}

static inline void
ndn_signature_disable_keylocator_keydigest(ndn_signature_t* signature){
  signature->enable_keydigest = 0;
}

static inline void
ndn_signature_disable_keylocator(ndn_signature_t* signature){
  signature->enable_keylocator = 0;
  signature->enable_keydigest = 0;
}

static inline int
ndn_signature_set_keylocator_keyname(ndn_signature_t* signature, ndn_name_t* input){
  if(signature->enable_keylocator == 0) return -1;
  if(signature->enable_keydigest == 1) return -1;
  signature->keylocator.type = -1; //default
  signature->keylocator.keyname = *input;

  return 0;
}

// will do memory copy
static inline int
ndn_signature_set_keylocator_keydigest(ndn_signature_t* signature, ndn_buffer_t* input){
  if(signature->enable_keylocator == 0) return -1;
  if(signature->enable_keydigest == 0) return -1;
  signature->keylocator.type = -1; //default
  memcpy(signature->keylocator_holder, input->value, input->size);
  signature->keylocator.keydigest.value = signature->keylocator_holder;
  signature->keylocator.keydigest.size = 32;

  return 0;
}

static inline void
ndn_signature_set_validityperiod(ndn_signature_t* signature, uint32_t notbefore, uint32_t notafter){
  signature->validityperiod.notbefore = notbefore; //default
  signature->validityperiod.notafter = notafter;
}

static inline uint32_t
signatureinfo_probe_block_size(const ndn_signature_t* signature){
  if(signature->enable_keylocator == 1){
    if(signature->enable_keydigest == 1) return 32 + 2 + 2 + 5;
    else{
      size_t keyname_size = ndn_name_probe_block_size(&signature->keylocator.keyname);
      size_t keylocator_var_size = encoder_get_var_size(keyname_size);
      size_t info_tlv_var_size = encoder_get_var_size(keyname_size + keylocator_var_size + 1 + 3);
      return keyname_size + keylocator_var_size + 1 + 3 + info_tlv_var_size + 1;
    }
  }
  else{
      return 5;
  }
}

static inline uint32_t
ndn_signature_probe_block_size(const ndn_signature_t* signature){
  size_t info_size = signatureinfo_probe_block_size(signature);
  size_t value_var_size = encoder_get_var_size(signature->signature_value.size);
  size_t value_size = signature->signature_value.size + value_var_size + 1;
  return info_size + value_size;
}

int
ndn_signature_tlv_encode(ndn_signature_t* signature, ndn_block_t* output);

int
ndn_signature_tlv_decode(ndn_signature_t* signature, ndn_block_t* output);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_SIGNATURE_H
