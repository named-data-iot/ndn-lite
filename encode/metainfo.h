#ifndef ENCODING_METAINFO_H
#define ENCODING_METAINFO_H

#include "tlv.h"
#include "encoder.h"
#include "decoder.h"
#include "name.h"
#include "ndn_constants.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Type to represent NDN metainfo.
 */
typedef struct ndn_metainfo {
    int32_t content_type;    /**< content type; -1 if not present */
    int32_t freshness;       /**< freshness period; -1 if not present */
    name_component_t finalblock_id;
} ndn_metainfo_t;

// will do memory copy
static inline int
ndn_metainfo_init(ndn_metainfo_t *meta, int32_t content_type, int32_t freshness, const name_component_t* finalblock_id){
    meta->content_type = content_type;
    meta->freshness = freshness;
    meta->finalblock_id.size = finalblock_id->size;
    meta->finalblock_id.type = finalblock_id->type;
    memcpy(meta->finalblock_id.value, finalblock_id->value, finalblock_id->size);
    return 0;
}

// will do memory copy
static inline int
ndn_metainfo_from_other(ndn_metainfo_t* meta, const ndn_metainfo_t* other){
    meta->content_type = other->content_type;
    meta->freshness = other->freshness;
    meta->finalblock_id.size = other->finalblock_id.size;
    meta->finalblock_id.type = other->finalblock_id.type;
    memcpy(meta->finalblock_id.value, other->finalblock_id.value, other->finalblock_id.size);
    return 0;
}

  

static inline uint32_t
ndn_metainfo_probe_block_size(ndn_metainfo_t* meta){
    size_t finalblockid_size = name_component_probe_block_size(&meta->finalblock_id);
    int contenttype_var_size = encoder_get_var_size((uint32_t)meta->content_type);
    int freshness_var_size = encoder_get_var_size((uint32_t)meta->freshness);
    
    int contenttype_tlv_size = 
        encoder_probe_block_size(TLV_ContentType, contenttype_var_size);  
    int freshness_tlv_size = 
        encoder_probe_block_size(TLV_FreshnessPeriod, freshness_var_size); 
    int finalblockid_tlv_size = 
        encoder_probe_block_size(TLV_FinalBlockId, finalblockid_size);                   

    int total_value_size = contenttype_tlv_size + freshness_tlv_size
                        + finalblockid_tlv_size;
                        
    return encoder_probe_block_size(TLV_MetaInfo, total_value_size);
}

int
ndn_metainfo_tlv_encode(ndn_metainfo_t *meta, ndn_block_t* output);

int
ndn_metainfo_tlv_decode(ndn_metainfo_t *meta, ndn_block_t* output);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NAME_H
