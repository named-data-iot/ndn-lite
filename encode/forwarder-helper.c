/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */
#include "forwarder-helper.h"
#include "tlv.h"
#include "../ndn-error-code.h"
#include "../ndn-constants.h"
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include "data.h"

/////////////////////////////////////////////////////////////////////////////////

size_t
tlv_get_tlvar(uint8_t* buf, size_t buflen, uint32_t* var){
  uint8_t first_byte = buf[0];
  if(first_byte < 253 && buflen >= 1){
    *var = first_byte;
    return 1;
  }
  else if(first_byte == 253 && buflen >= 3) {
    *var = ((uint32_t)buf[1] << 8) + buf[2];
    return 3;
  }
  else if (first_byte == 254 && buflen >= 5) {
    *var = ((uint32_t)buf[1] << 24) +
           ((uint32_t)buf[2] << 16) +
           ((uint32_t)buf[3] << 8) +
           ((uint32_t)buf[4]);
    return 5;
  }
  else {
    return 0;
  }
}

uint8_t*
tlv_get_type_length(uint8_t* buf, size_t buflen, uint32_t* type, uint32_t* length){
  uint32_t siz;
  uint8_t* ptr = buf;

  siz = tlv_get_tlvar(ptr, buflen, type);
  ptr += siz;
  buflen -= siz;
  if(siz == 0){
    return NULL;
  }

  siz = tlv_get_tlvar(ptr, buflen, length);
  ptr += siz;
  buflen -= siz;
  if(siz == 0){
    return NULL;
  }

  return ptr;
}

int
tlv_check_type_length(uint8_t* buf, size_t buflen, uint32_t type){
  uint32_t real_type, real_len;
  uint8_t* ptr;

  if(buf == NULL){
    return NDN_INVALID_POINTER;
  }
  ptr = tlv_get_type_length(buf, buflen, &real_type, &real_len);
  if(ptr == NULL){
    return NDN_OVERSIZE_VAR;
  }
  if(real_type != type){
    return NDN_WRONG_TLV_TYPE;
  }
  if(real_len != buflen - (ptr - buf)){
    return NDN_WRONG_TLV_LENGTH;
  }
  return NDN_SUCCESS;
}

static uint64_t
tlv_get_uint(uint8_t* buf, size_t buflen){
  uint64_t ret = 0;
  while(buflen --){
    ret = (ret << (uint64_t)8) + buf[0];
  }
  return ret;
}

int
tlv_interest_get_header(uint8_t* interest,
                        size_t buflen,
                        interest_options_t* options,
                        uint8_t** name,
                        size_t* name_len)
{
  uint32_t real_type, real_len;
  uint8_t* ptr;

  ptr = tlv_get_type_length(interest, buflen, &real_type, &real_len);
  if(ptr == NULL){
    return NDN_OVERSIZE_VAR;
  }
  if(real_type != TLV_Interest){
    return NDN_WRONG_TLV_TYPE;
  }
  if(real_len != buflen - (ptr - interest)){
    return NDN_WRONG_TLV_LENGTH;
  }

  // Name
  *name = ptr;
  ptr = tlv_get_type_length(ptr, buflen - (ptr - interest), &real_type, &real_len);
  if(ptr == NULL){
    return NDN_OVERSIZE_VAR;
  }
  if(real_type != TLV_Name){
    return NDN_UNSUPPORTED_FORMAT;
  }
  *name_len = real_len;
  ptr += real_len;

  // Options
  if(options == NULL){
    return NDN_SUCCESS;
  }
  options->can_be_prefix = false;
  options->must_be_fresh = false;
  options->lifetime = NDN_DEFAULT_INTEREST_LIFETIME;
  options->hop_limit = 0;
  options->nonce = 0;
  while(ptr < interest + buflen){
    ptr = tlv_get_type_length(ptr, buflen - (ptr - interest), &real_type, &real_len);
    if(ptr == NULL){
      return NDN_OVERSIZE_VAR;
    }
    if(real_type == TLV_CanBePrefix){
      options->can_be_prefix = true;
    }else if(real_type == TLV_MustBeFresh){
      options->must_be_fresh = true;
    }else if(real_type == TLV_HopLimit){
      options->hop_limit = *ptr;
    }else if(real_type == TLV_Nonce){
      options->nonce = *(uint32_t*)ptr;
    }else if(real_type == TLV_InterestLifetime){
      options->lifetime = tlv_get_uint(ptr, real_len);
    }
    ptr += real_len;
  }
  return NDN_SUCCESS;
}

int
tlv_data_get_name(uint8_t* data,
                  size_t buflen,
                  uint8_t** name,
                  size_t* name_len)
{
  uint32_t real_type, real_len;
  uint8_t* ptr;

  ptr = tlv_get_type_length(data, buflen, &real_type, &real_len);
  if(ptr == NULL){
    return NDN_OVERSIZE_VAR;
  }
  if(real_type != TLV_Data){
    return NDN_WRONG_TLV_TYPE;
  }
  if(real_len != buflen - (ptr - data)){
    return NDN_WRONG_TLV_LENGTH;
  }

  // Name
  *name = ptr;
  ptr = tlv_get_type_length(ptr, buflen - (ptr - data), &real_type, &real_len);
  if(ptr == NULL){
    return NDN_OVERSIZE_VAR;
  }
  if(real_type != TLV_Name){
    return NDN_UNSUPPORTED_FORMAT;
  }
  *name_len = real_len;

  return NDN_SUCCESS;
}

uint8_t*
tlv_interest_get_hoplimit_ptr(uint8_t* interest, size_t buflen){
  uint32_t real_type, real_len;
  uint8_t* ptr;

  ptr = tlv_get_type_length(interest, buflen, &real_type, &real_len);
  if(ptr == NULL){
    return NULL;
  }
  while(ptr < interest + buflen){
    ptr = tlv_get_type_length(ptr, buflen - (ptr - interest), &real_type, &real_len);
    if(ptr == NULL){
      return NULL;
    }
    if(real_type == TLV_HopLimit){
      return ptr;
    }
    ptr += real_len;
  }
  return NULL;
}

/////////////////////////////////////////////////////////////////////////////////

static void
tlv_make_segno(name_component_t* comp, uint64_t val){
  int i;
  uint64_t cur;
  comp->type = TLV_GenericNameComponent;
  cur = val;
  for(i = 0; cur > 0; i ++){
    cur /= 0x100;
  }
  if(i == 0){
    i ++;
  }

  comp->size = i + 1;
  cur = val;
  for(; i >= 0; i --){
    comp->value[i] = (uint8_t)(cur % 0x100);
    cur /= 0x100;
  }
}

int
tlv_make_data(uint8_t* buf, size_t buflen, size_t* result_size, int argc, ...){
  static ndn_data_t data;
  ndn_decoder_t decoder;
  ndn_encoder_t encoder;
  va_list vl;
  int i, argtype;
  int ret = NDN_SUCCESS;
  void* arg_ptr = NULL;
  uint8_t* content_buf_ptr = NULL;
  ndn_name_t* identity = NULL;
  void* key_ptr = NULL;
  uint64_t segno = (uint64_t)-1;

  // Default values
  ndn_metainfo_init(&data.metainfo);
  data.content_size = 0;
  data.name.components_size = 0;
  data.signature.sig_type = NDN_SIG_TYPE_DIGEST_SHA256;

  va_start(vl, argc);
  for(i = 0; i < argc && ret == NDN_SUCCESS; i ++){
    argtype = va_arg(vl, enum TLV_MAKEDATA_ARG_TYPE);
    switch(argtype){
      case TLV_MAKEDATA_NAME_PTR:
        arg_ptr = va_arg(vl, void*);
        if(arg_ptr == NULL){
          ret = NDN_INVALID_POINTER;
          break;
        }
        data.name = *(ndn_name_t*)arg_ptr;
        break;

      case TLV_MAKEDATA_NAME_BUF:
        arg_ptr = va_arg(vl, void*);
        if(arg_ptr == NULL){
          ret = NDN_INVALID_POINTER;
          break;
        }
        decoder_init(&decoder, (uint8_t*)arg_ptr, INT_MAX);
        ret = ndn_name_tlv_decode(&decoder, &data.name);
        break;

      case TLV_MAKEDATA_NAME_SEGNO_U64:
        segno = va_arg(vl, uint64_t);
        break;

      case TLV_MAKEDATA_CONTENTTYPE_U8:
        ndn_metainfo_set_content_type(&data.metainfo, (uint8_t)va_arg(vl, uint32_t));
        break;

      case TLV_MAKEDATA_FRESHNESSPERIOD_U64:
        ndn_metainfo_set_freshness_period(&data.metainfo, va_arg(vl, uint32_t));
        break;

      case TLV_MAKEDATA_FINALBLOCKID_PTR:
        arg_ptr = va_arg(vl, void*);
        if(arg_ptr == NULL){
          ret = NDN_INVALID_POINTER;
          break;
        }
        ndn_metainfo_set_final_block_id(&data.metainfo, (name_component_t*)arg_ptr);
        break;

      case TLV_MAKEDATA_FINALBLOCKID_BUF:
        arg_ptr = va_arg(vl, void*);
        if(arg_ptr == NULL){
          ret = NDN_INVALID_POINTER;
          break;
        }
        decoder_init(&decoder, (uint8_t*)arg_ptr, INT_MAX);
        ret = name_component_tlv_decode(&decoder, &data.metainfo.final_block_id);
        data.metainfo.enable_FinalBlockId = true;
        break;

      case TLV_MAKEDATA_FINALBLOCKID_U64:
        tlv_make_segno(&data.metainfo.final_block_id, va_arg(vl, uint64_t));
        data.metainfo.enable_FinalBlockId = true;
        break;

      case TLV_MAKEDATA_CONTENT_BUF:
        content_buf_ptr = va_arg(vl, uint8_t*);
        break;

      case TLV_MAKEDATA_CONTENT_SIZE:
        data.content_size = va_arg(vl, size_t);
        break;

      case TLV_MAKEDATA_SIGTYPE_U8:
        ret = ndn_signature_set_signature_type(&data.signature, (uint8_t)va_arg(vl, uint32_t));
        break;

      case TLV_MAKEDATA_IDENTITYNAME_PTR:
        identity = va_arg(vl, ndn_name_t*);
        break;

      case TLV_MAKEDATA_KEY_PTR:
        key_ptr = va_arg(vl, void*);
        break;

      case TLV_MAKEDATA_SIGTIME_U64:
        ndn_signature_set_timestamp(&data.signature, va_arg(vl, uint64_t));
        break;

      default:
        ret = NDN_INVALID_ARG;
        break;
    }
  }
  va_end(vl);
  if(ret != NDN_SUCCESS){
    return ret;
  }

  // Copy content
  if(data.content_size > NDN_CONTENT_BUFFER_SIZE){
    return NDN_OVERSIZE;
  }
  if(data.content_size > 0 && content_buf_ptr != NULL){
    memcpy(data.content_value, content_buf_ptr, data.content_size);
  }

  // Check name
  if(data.name.components_size == 0){
    return NDN_INVALID_ARG;
  }
  if(segno != (uint64_t)-1){
    tlv_make_segno(&data.name.components[data.name.components_size], segno);
    data.name.components_size += 1;
  }

  // Encode
  encoder_init(&encoder, buf, buflen);
  switch(data.signature.sig_type){
    case NDN_SIG_TYPE_DIGEST_SHA256:
      ret = ndn_data_tlv_encode_digest_sign(&encoder, &data);
      break;

    case NDN_SIG_TYPE_ECDSA_SHA256:
      if(identity == NULL || key_ptr == NULL){
        ret = NDN_INVALID_POINTER;
      }else{
        ret = ndn_data_tlv_encode_ecdsa_sign(&encoder, &data, identity, (ndn_ecc_prv_t*)key_ptr);
      }
      break;

    case NDN_SIG_TYPE_HMAC_SHA256:
      if(identity == NULL || key_ptr == NULL){
        ret = NDN_INVALID_POINTER;
      }else{
        ret = ndn_data_tlv_encode_hmac_sign(&encoder, &data, identity, (ndn_hmac_key_t*)key_ptr);
      }
      break;

    default:
      ret = NDN_SEC_UNSUPPORT_SIGN_TYPE;
      break;
  }

  if(result_size != NULL){
    *result_size = encoder.offset;
  }

  return ret;
}