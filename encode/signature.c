#include "signature.h"
#include <stdio.h>

int
ndn_signature_tlv_encode(ndn_signature_t* signature, ndn_block_t* output){
    ndn_encoder_t encoder;

    encoder_init(&encoder, output->value, output->size);

    // signatureinfo header
    encoder_append_type(&encoder, TLV_SignatureInfo);
    size_t estimate = signatureinfo_probe_block_size(signature);
    encoder_append_length(&encoder, estimate);

    // signatureinfo
    encoder_append_type(&encoder, TLV_SignatureType);
    size_t signature_type_size = encoder_get_var_size(signature->type);
    encoder_append_length(&encoder, signature_type_size);
    encoder_append_type(&encoder, signature->type);

    // keylocator 
    if(signature->enable_keylocator == 1){
        encoder_append_type(&encoder, TLV_KeyLocator);
        if(signature->enable_keydigest == 1){
            encoder_append_length(&encoder, 32 + 2);
            encoder_append_type(&encoder, TLV_KeyLocatorDigest);
            encoder_append_length(&encoder, 32);
            //encode keydigest
            encoder_append_raw_buffer_value(&encoder, signature->keylocator.keydigest.value, 
                                            signature->keylocator.keydigest.size);
        }

        else{
            size_t keyname_size = ndn_name_probe_block_size(&signature->keylocator.keyname);
            encoder_append_length(&encoder, keyname_size);
            ndn_name_tlv_encode(&encoder, &signature->keylocator.keyname);
        }
    }

    // signaturevalue
    encoder_append_type(&encoder, TLV_SignatureValue);
    switch(signature->type){
        case NDN_SIG_TYPE_DIGEST_SHA256:
            encoder_append_length(&encoder, 32);
            break;
            
        case NDN_SIG_TYPE_HMAC_SHA256:
            encoder_append_length(&encoder, 32);
            break;

        case NDN_SIG_TYPE_ECDSA_SHA256:
            encoder_append_length(&encoder, 64);
            break;

        case NDN_SIG_TYPE_RSA_SHA256:
            encoder_append_length(&encoder, 128); 
            break;
    }    
    encoder_append_raw_buffer_value(&encoder, signature->signature_value.value, 
                                    signature->signature_value.size);

    output->size = encoder.offset;
    return 0;
}

int
ndn_signature_tlv_decode(ndn_signature_t* signature, ndn_block_t* block){
    ndn_decoder_t decoder;
    uint32_t probe;

signature->enable_keylocator = 0;
signature->enable_keydigest = 0;

    decoder_init(&decoder, block->value, block->size);

    // signatureinfo header
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &probe);

    // signature type tlv
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &probe);
    decoder_get_type(&decoder, &signature->type);
    
    //initialize keylocator
    switch(signature->type){
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
            signature->signature_value.size = 128;
            break;
    } 

    // check keylocator block
    decoder_get_type(&decoder, &probe);
    if(probe == TLV_KeyLocator){
        signature->enable_keylocator = 1;
        decoder_get_length(&decoder, &probe);
        size_t keyname_length = probe;

        // keyname or keydigest
        decoder_get_type(&decoder, &probe);
        if(probe == TLV_KeyLocatorDigest){
            signature->enable_keydigest = 1;
            decoder_get_length(&decoder, &probe);
            signature->keylocator.keydigest.size = probe;
            signature->keylocator.keydigest.value = signature->keylocator_holder;
            decoder_get_raw_buffer_value(&decoder, signature->keylocator.keydigest.value,
                                          signature->keylocator.keydigest.size);
        }
        else{
            signature->enable_keydigest = 0;
            decoder_move_backward(&decoder, 1);

            // should replace with name tlv decode later
            uint8_t rest[keyname_length];
            memcpy(rest, block->value + decoder.offset, keyname_length);
            decoder_move_forward(&decoder, keyname_length);
            ndn_name_from_block(&signature->keylocator.keyname, rest, keyname_length);
        }
    }
    else decoder_move_backward(&decoder, 1);

    // signaturevalue
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &probe);
    signature->signature_value.value = signature->value_holder;
    decoder_get_raw_buffer_value(&decoder, signature->signature_value.value,
                                          signature->signature_value.size);
                                              
    block->size = decoder.offset;
    return 0;
}