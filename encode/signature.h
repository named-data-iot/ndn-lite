#ifndef ENCODING_SIGNATURE_H
#define ENCODING_SIGNATURE_H

#include "tlv.h"
#include "encoder.h"
#include "decoder.h"
#include "block.h"
#include "key-types.h"
#include "name.h"
#include "ndn_constants.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A Signature struct holds the signature bits and other info representing
 * the signature in a data packet or signed interest. We use one structure which
 * is a union of all the fields from the different known signature types. This
 * lets us avoid the infrastructure to simulate an abstract base class with
 * subclasses and virtual methods.
 */
struct ndn_signature {
  uint32_t type;                /**< -1 for unspecified */
  ndn_buffer_t signature_value;
  ndn_buffer_t signature_info; /**< used with Generic */
  
  uint8_t enable_keylocator;
  uint8_t data_holder[NDN_SIGNATURE_BUFFER_SIZE];
  
  ndn_keylocator_t keylocator; /**< used with Sha256WithRsaSignature,
                                     * Sha256WithEcdsaSignature, HmacWithSha256Signature */
  ndn_validityperiod_t validityperiod; /**< used with Sha256WithRsaSignature,
                                     * Sha256WithEcdsaSignature */
}ndn_signature_t;

static inline int
ndn_signature_init(ndn_signature_t* signature, uint32_t type){
  if(type != NDN_SIG_TYPE_DIGEST_SHA256 && type != NDN_SIG_TYPE_ECDSA_SHA256
     type != NDN_SIG_TYPE_HMAC_SHA256 && type != NDN_SIG_TYPE_RSA_SHA256)
  return -1;

  switch(type){
    case NDN_SIG_TYPE_DIGEST_SHA256
        signaure->enable_keylocator = 0;
        signature->signature_value.size = 32; 
        break;

    case NDN_SIG_TYPE_ECDSA_SHA256
        signature->enable_keylocator = 1;
        signature->signature_value.size = 64; 
        break;

    case NDN_SIG_TYPE_HMAC_SHA256
        signature->enable_keylocator = 1;
        signature->signature_value.size = 32;
        break;

    case NDN_SIG_TYPE_RSA_SHA256
        signature->enable_keylocator = 1;
        signature->signature_value.size = 124;
        break;
  } 

  signature->signature_value.value = data_holder;
  signature->type = type;
  return 0;
}

// will do memory copy
static inline void
ndn_signature_set_signataure_value(ndn_signature_t* signature, ndn_buffer_t* input){
  signature->signature_value.size = input->size;
  memcpy(signature->signature_value.value, input->value, input->size);
}

static inline int
ndn_signature_set_keylocator_keyname(ndn_signature_t* signature, ndn_name_t* input){
  if(signature->enable_keylocator == 0) return -1;
  signature->keylocator.type = -1; //default
  signature->keylocator.keyname = *input;
}

static inline void
ndn_signature_set_keylocator_keydata(ndn_signature_t* signature, ndn_buffer_t* input){
  if(signature->enable_keylocator == 0) return -1;
  signature->keylocator.type = -1; //default
  signature->keylocator.keydata = *input;
}

static inline void
ndn_signature_set_validityperiod(ndn_signature_t* signature, uint32_t notbefore, uint32_t notafter){
  signature->validityperiod.notbefore = notbefore; //default
  signature->validityperiod.notafter = notafter;
}

static inline uint32_t
ndn_signature_probe_block_size(const ndn_signature_t* siganture){

}

int
ndn_signature_tlv_encode(ndn_signature_t* signature, ndn_block_t* output);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_SIGNATURE_H
