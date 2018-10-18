#ifndef NDN_SECURITY_SIGN_VERIFY_H_
#define NDN_SECURITY_SIGN_VERIFY_H_

#include "encode/block.h"
#include "encode/key-types.h"
#include "encode/ndn_constants.h"


#ifdef __cplusplus
extern "C" {
#endif

int security_sign_value(ndn_block_t* input, uint8_t* key_data, ndn_buffer_t* output, 
                        uint32_t key_size, uint32_t type, 
                        uint32_t ecdsa_type);

int security_verify_value(ndn_block_t* input, uint8_t* key_data, ndn_buffer_t* value, 
                          uint32_t key_size, uint32_t type, 
                          uint32_t ecdsa_type);

static inline int
ndn_security_ecdsa_sign_value(ndn_block_t* input, ndn_ecdsa_t* key, ndn_buffer_t* output){
    return security_sign_value(input, key->pvt, output, 32, 
                               NDN_SIG_TYPE_ECDSA_SHA256, key->type);
}

static inline int
ndn_security_ecdsa_verify_value(ndn_block_t* input, ndn_ecdsa_t* key, ndn_buffer_t* value){
    return security_sign_value(input, key->pub, value, 64, 
                               NDN_SIG_TYPE_ECDSA_SHA256, key->type);
}

static inline int
ndn_security_hmac_sign_value(ndn_block_t* input, ndn_hmac_t* key, ndn_buffer_t* output){
    return security_sign_value(input, key->keydata, output, key->size, 
                               NDN_SIG_TYPE_HMAC_SHA256, 0);
}

static inline int
ndn_security_hmac_verify_value(ndn_block_t* input, ndn_hmac_t* key, ndn_buffer_t* value){
    return security_sign_value(input, key->keydata, value, key->size, 
                               NDN_SIG_TYPE_HMAC_SHA256, 0);
}

static inline int
ndn_security_digest_sign_value(ndn_block_t* input, ndn_buffer_t* output){
    return security_sign_value(input, NULL, output, 0, 
                               NDN_SIG_TYPE_DIGEST_SHA256, 0);
}

static inline int
ndn_security_digest_verify_value(ndn_block_t* input, ndn_buffer_t* value){
    return security_sign_value(input, NULL, value, 0, 
                               NDN_SIG_TYPE_DIGEST_SHA256, 0);
}
#ifdef __cplusplus
}
#endif

#endif /* NDN_SECURITY_SIGN_VERIFY_H_ */