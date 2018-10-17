#include "siganture.h"
#include <stdio.h>

int
ndn_signature_tlv_encode(ndn_signature_t* signature, ndn_block_t* block){
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

    }

    // signaturevalue
    encoder_append_type(&encoder, TLV_SignatureValue);
    switch(signature->type){
        case NDN_SIG_TYPE_DIGEST_SHA256
            encoder_append_length(&encoder, 32);
            break;
            
        case NDN_SIG_TYPE_HMAC_SHA256
            encoder_append_length(&encoder, 32);
            break;

        case NDN_SIG_TYPE_ECDSA_SHA256
            encoder_append_length(&encoder, 64);
            break;

        case NDN_SIG_TYPE_RSA_SHA256
            encoder_append_length(&encoder, 128); 
            break;
    }    
    encoder_append_raw_buffer_value(&encoder, &signature->signature_value.value, signature->signature_value.size);

    output->size = encoder.offset;
  return 0;
}

int
ndn_metainfo_tlv_decode(ndn_metainfo_t* meta, ndn_block_t* block)
{
    ndn_decoder_t decoder;
    uint32_t probe;
    decoder_init(&decoder, block->value, block->size);
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &probe);

    //decode content_type
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &probe);
    decoder_get_integer(&decoder, (uint32_t*)&meta->content_type);

    //decode freshness
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &probe);
    decoder_get_integer(&decoder, (uint32_t*)&meta->freshness);

    //decode finalblockid
    name_component_block_t comp_block;
    decoder_get_type(&decoder, &probe);
    decoder_get_length(&decoder, &comp_block.size);
    decoder_get_raw_buffer_value(&decoder, comp_block.value, comp_block.size);
    name_component_from_block(&meta->finalblock_id, &comp_block);

    return 0;
}

int
ndn_metainfo_tlv_encode(ndn_metainfo_t* meta, ndn_block_t* output)
{
    ndn_encoder_t encoder;

    encoder_init(&encoder, output->value, output->size);
    encoder_append_type(&encoder, TLV_MetaInfo);
    size_t estimate = ndn_metainfo_probe_block_size(meta);
    encoder_append_length(&encoder, estimate);

    //encode content_type  
    encoder_append_type(&encoder, TLV_ContentType);
    size_t contenttype_var_size = encoder_get_var_size((uint32_t)meta->content_type);
    encoder_append_length(&encoder, contenttype_var_size);
    encoder_append_integer(&encoder, (uint32_t)meta->content_type);

    //encode freshness 
    encoder_append_type(&encoder, TLV_FreshnessPeriod);
    size_t freshness_var_size = encoder_get_var_size((uint32_t)meta->freshness);
    encoder_append_length(&encoder, freshness_var_size);
    encoder_append_integer(&encoder, (uint32_t)meta->freshness);

    //encode finalblockid
    encoder_append_type(&encoder, TLV_FinalBlockId);
    size_t comp_size = name_component_probe_block_size(&meta->finalblock_id);
    encoder_append_length(&encoder, comp_size);
    name_component_tlv_encode(&encoder, &meta->finalblock_id);

    output->size = encoder.offset;
  return 0;
}
