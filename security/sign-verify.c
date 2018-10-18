#include <inttypes.h>
#include <stdio.h>
#include <crypto/ciphers.h>
#include <crypto/modes/ccm.h>
#include <hashes/sha256.h>
#include <random.h>
#include <uECC.h>

#include <stdlib.h>
#include <string.h>
#include "sign-verify.h"

#ifndef FEATURE_PERIPH_HWRNG
typedef struct uECC_SHA256_HashContext {
    uECC_HashContext uECC;
    sha256_context_t ctx;
} uECC_SHA256_HashContext;

static void _init_sha256(const uECC_HashContext *base)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_init(&context->ctx);
}

static void _update_sha256(const uECC_HashContext *base,
                           const uint8_t *message,
                           unsigned message_size)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_update(&context->ctx, message, message_size);
}

static void _finish_sha256(const uECC_HashContext *base, uint8_t *hash_result)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_final(&context->ctx, hash_result);
}
#endif


int security_sign_value(ndn_block_t* input, uint8_t* key_data, ndn_buffer_t* output, 
                        uint32_t key_size, uint32_t type, uint32_t ecdsa_type)
{
    switch(type){
        case NDN_SIG_TYPE_DIGEST_SHA256:
            sha256(input->value, input->size, output->value);
            output->size = 32;
            break;
        case NDN_SIG_TYPE_ECDSA_SHA256:
        {
            if(key_size != 32) return -1;
            uint8_t h[32] = {0};
            uECC_Curve curve;
            switch(ecdsa_type){
                case NDN_ECDSA_CURVE_SECP160R1:
                    curve = uECC_secp160r1();
                    break;
                case NDN_ECDSA_CURVE_SECP192R1:
                    curve = uECC_secp192r1();
                    break;
                case NDN_ECDSA_CURVE_SECP224R1:
                    curve = uECC_secp224r1();
                    break;
                case NDN_ECDSA_CURVE_SECP256R1:
                    curve = uECC_secp256r1();
                    break;
                case NDN_ECDSA_CURVE_SECP256K1:
                    curve = uECC_secp256k1();
                    break;
            }

            sha256(input->value, input->size, h);

        #ifndef FEATURE_PERIPH_HWRNG
            // allocate memory on heap to avoid stack overflow
            uint8_t tmp[32 + 32 + 64];
            uECC_SHA256_HashContext HashContext;
            uECC_SHA256_HashContext* ctx = &HashContext;

            ctx->uECC.init_hash = &_init_sha256;
            ctx->uECC.update_hash = &_update_sha256;
            ctx->uECC.finish_hash = &_finish_sha256;
            ctx->uECC.block_size = 64;
            ctx->uECC.result_size = 32;
            ctx->uECC.tmp = tmp;

            int res = uECC_sign_deterministic(key_data, h, sizeof(h), &ctx->uECC,
                                                    output->value, curve);
            if (res == 0) return -1;
        #else
            res = uECC_sign(key_data, h, sizeof(h), output->value, curve);
            if (res == 0) return -1;
        #endif
            output->size = 64;
            return 0; //success
        }
            break;
        case NDN_SIG_TYPE_HMAC_SHA256:
            hmac_sha256(key_data, key_size, (const unsigned*)input->value,
                        input->size, output->value);
            output->size = 32;
            break;
        case NDN_SIG_TYPE_RSA_SHA256:
            //TODO: rsa support
            break;
        
        default:
            break;
    }
    return 0;
}

int security_verify_value(ndn_block_t* input, uint8_t* key_data, ndn_buffer_t* value, 
                        uint32_t key_size, uint32_t type, uint32_t ecdsa_type)
{
    switch(type){
        case NDN_SIG_TYPE_DIGEST_SHA256:
            if (value->size != 32) return -1;      
            uint8_t h[32] = {0};
            sha256(input->value, input->size, h);
            if (memcmp(h, value->value, sizeof(h)) != 0) return -1;
            else return 0;
            break;
        case NDN_SIG_TYPE_ECDSA_SHA256:
        {
            if (value->size != 64) return -1;
            if (key_data == NULL || key_size != 64) return -1;
            uint8_t h[32] = {0};
            sha256(input->value, input->size, h);
            uECC_Curve curve;
            switch(ecdsa_type){
                case NDN_ECDSA_CURVE_SECP160R1:
                    curve = uECC_secp160r1();
                    break;
                case NDN_ECDSA_CURVE_SECP192R1:
                    curve = uECC_secp192r1();
                    break;
                case NDN_ECDSA_CURVE_SECP224R1:
                    curve = uECC_secp224r1();
                    break;
                case NDN_ECDSA_CURVE_SECP256R1:
                    curve = uECC_secp256r1();
                    break;
                case NDN_ECDSA_CURVE_SECP256K1:
                    curve = uECC_secp256k1();
                    break;
            }
            if (uECC_verify(key_data, h, sizeof(h),
                            value->value, curve) == 0) return -1;
            else
                return 0;
        }
            break;
        case NDN_SIG_TYPE_HMAC_SHA256:
        {
            if (value->size != 32) return -1;
            uint8_t h[32] = {0};
            if (key_data == NULL || key_size <= 0) return -1;
            hmac_sha256(key_data, key_size, (const unsigned*)input->value,
                        input->size, h);
            if (memcmp(h, value->value, sizeof(h)) != 0) return -1;
            else return 0;
        }
            break;
        case NDN_SIG_TYPE_RSA_SHA256:
            //TODO: rsa support
            break;

        default:
            break;
    }
    return 0;
}                