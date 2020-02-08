/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "wrapper-api.h"
#include "forwarder-helper.h"
#include "tlv.h"
#include "../ndn-error-code.h"
#include "../ndn-constants.h"
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include "data.h"
#include "interest.h"
#include "signed-interest.h"

void
tlv_encode_segno(name_component_t* comp, uint64_t val)
{
  int i;
  uint64_t cur;
  comp->type = TLV_GenericNameComponent;
  cur = val;
  for (i = 0; cur > 0; i ++) {
    cur /= 0x100;
  }
  if (i == 0) {
    i ++;
  }

  comp->size = i + 1;
  cur = val;
  for (; i >= 0; i --) {
    comp->value[i] = (uint8_t)(cur % 0x100);
    cur /= 0x100;
  }
}

uint64_t
tlv_decode_segno(name_component_t* comp)
{
  int i;
  uint64_t ret = 0;

  if (comp->type != TLV_GenericNameComponent ||
     comp->size < 2 ||
     comp->value[0] != 0) {
    return (uint64_t)-1;
  }
  for (i = 1; i < comp->size; i ++) {
    ret = ret * 0x100 + comp->value[i];
  }
  return ret;
}

int
tlv_make_data(uint8_t* buf, size_t buflen, size_t* result_size, int argc, ...)
{
  static ndn_data_t data;
  ndn_decoder_t decoder;
  ndn_encoder_t encoder;
  va_list vl;
  int i;
  enum TLV_DATAARG_TYPE argtype;
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
  for (i = 0; i < argc && ret == NDN_SUCCESS; i++) {
    argtype = va_arg(vl, int);
    switch(argtype) {
      case TLV_DATAARG_NAME_PTR:
        arg_ptr = va_arg(vl, void*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        data.name = *(ndn_name_t*)arg_ptr;
        break;

      case TLV_DATAARG_NAME_BUF:
        arg_ptr = va_arg(vl, void*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        decoder_init(&decoder, (uint8_t*)arg_ptr, INT_MAX);
        ret = ndn_name_tlv_decode(&decoder, &data.name);
        break;

      case TLV_DATAARG_NAME_SEGNO_U64:
        segno = va_arg(vl, uint64_t);
        break;

      case TLV_DATAARG_CONTENTTYPE_U8:
        ndn_metainfo_set_content_type(&data.metainfo, (uint8_t)va_arg(vl, uint32_t));
        break;

      case TLV_DATAARG_FRESHNESSPERIOD_U64:
        ndn_metainfo_set_freshness_period(&data.metainfo, va_arg(vl, uint64_t));
        break;

      case TLV_DATAARG_FINALBLOCKID_PTR:
        arg_ptr = va_arg(vl, void*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        ndn_metainfo_set_final_block_id(&data.metainfo, (name_component_t*)arg_ptr);
        break;

      case TLV_DATAARG_FINALBLOCKID_BUF:
        arg_ptr = va_arg(vl, void*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        decoder_init(&decoder, (uint8_t*)arg_ptr, INT_MAX);
        ret = name_component_tlv_decode(&decoder, &data.metainfo.final_block_id);
        data.metainfo.enable_FinalBlockId = true;
        break;

      case TLV_DATAARG_FINALBLOCKID_U64:
        tlv_encode_segno(&data.metainfo.final_block_id, va_arg(vl, uint64_t));
        data.metainfo.enable_FinalBlockId = true;
        break;

      case TLV_DATAARG_CONTENT_BUF:
        content_buf_ptr = va_arg(vl, uint8_t*);
        break;

      case TLV_DATAARG_CONTENT_SIZE:
        data.content_size = va_arg(vl, size_t);
        break;

      case TLV_DATAARG_SIGTYPE_U8:
        ret = ndn_signature_set_signature_type(&data.signature, (uint8_t)va_arg(vl, uint32_t));
        break;

      case TLV_DATAARG_IDENTITYNAME_PTR:
        identity = va_arg(vl, ndn_name_t*);
        break;

      case TLV_DATAARG_SIGKEY_PTR:
        key_ptr = va_arg(vl, void*);
        break;

      case TLV_DATAARG_SIGTIME_U64:
        ndn_signature_set_timestamp(&data.signature, va_arg(vl, uint64_t));
        break;

      default:
        ret = NDN_INVALID_ARG;
        break;
    }
  }
  va_end(vl);
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Copy content
  if (data.content_size > 0 && content_buf_ptr != NULL) {
    ret = ndn_data_set_content(&data, content_buf_ptr, data.content_size);
  }
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Check name
  if (data.name.components_size == 0) {
    return NDN_INVALID_ARG;
  }
  if (segno != (uint64_t) - 1) {
    tlv_encode_segno(&data.name.components[data.name.components_size], segno);
    data.name.components_size += 1;
  }

  // Encode
  encoder_init(&encoder, buf, buflen);
  switch (data.signature.sig_type) {
    case NDN_SIG_TYPE_DIGEST_SHA256:
      ret = ndn_data_tlv_encode_digest_sign(&encoder, &data);
      break;

    case NDN_SIG_TYPE_ECDSA_SHA256:
      if (identity == NULL || key_ptr == NULL) {
        ret = NDN_INVALID_POINTER;
      }
      else {
        ret = ndn_data_tlv_encode_ecdsa_sign(&encoder, &data, identity, (ndn_ecc_prv_t*)key_ptr);
      }
      break;

    case NDN_SIG_TYPE_HMAC_SHA256:
      if (identity == NULL || key_ptr == NULL) {
        ret = NDN_INVALID_POINTER;
      }
      else {
        ret = ndn_data_tlv_encode_hmac_sign(&encoder, &data, identity, (ndn_hmac_key_t*)key_ptr);
      }
      break;

    default:
      ret = NDN_SEC_UNSUPPORT_SIGN_TYPE;
      break;
  }

  if (result_size != NULL) {
    *result_size = encoder.offset;
  }

  return ret;
}

int
tlv_parse_data(uint8_t* buf, size_t buflen, int argc, ...)
{
  static ndn_data_t data;
  va_list vl;
  int i, ret = NDN_SUCCESS;
  enum TLV_DATAARG_TYPE argtype;
  uint32_t block_type, block_len;
  uint8_t *ptr, *valptr, *end = buf + buflen;
  uint8_t **namebuf_ptr = NULL;
  uint8_t **finalblockid_ptr = NULL;
  uint8_t **content_ptr = NULL;
  void *arg_ptr = NULL;
  void *key_ptr = NULL;
  bool verify_sig = false;

  // Check type and length
  ptr = tlv_get_type_length(buf, buflen, &block_type, &block_len);
  if (ptr == NULL) {
    return NDN_OVERSIZE_VAR;
  }
  if (block_type != TLV_Data) {
    return NDN_WRONG_TLV_TYPE;
  }
  if (block_len != end - ptr) {
    return NDN_WRONG_TLV_LENGTH;
  }

  // Decode data
  ret = ndn_data_tlv_decode_no_verify(&data, buf, buflen, NULL, NULL);
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Parse args
  va_start(vl, argc);
  for(i = 0; i < argc && ret == NDN_SUCCESS; i ++) {
    argtype = va_arg(vl, int);
    switch(argtype) {
      case TLV_DATAARG_NAME_PTR:
        arg_ptr = va_arg(vl, ndn_name_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *(ndn_name_t*)arg_ptr = data.name;
        break;

      case TLV_DATAARG_NAME_BUF:
        namebuf_ptr = va_arg(vl, uint8_t**);
        if (namebuf_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *namebuf_ptr = NULL;
        break;

      case TLV_DATAARG_NAME_SEGNO_U64:
        arg_ptr = va_arg(vl, uint64_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (data.name.components_size > 0) {
          *(uint64_t*)arg_ptr = tlv_decode_segno(&data.name.components[data.name.components_size - 1]);
        }
        else {
          ret = NDN_UNSUPPORTED_FORMAT;
        }
        break;

      case TLV_DATAARG_CONTENTTYPE_U8:
        arg_ptr = va_arg(vl, uint8_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (data.metainfo.enable_ContentType) {
          *(uint8_t*)arg_ptr = data.metainfo.content_type;
        }
        else {
          *(uint8_t*)arg_ptr = 0xFF;
        }
        break;

      case TLV_DATAARG_FRESHNESSPERIOD_U64:
        arg_ptr = va_arg(vl, uint64_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (data.metainfo.enable_FreshnessPeriod) {
          *(uint64_t*)arg_ptr = data.metainfo.freshness_period;
        }
        else {
          *(uint64_t*)arg_ptr = 0;
        }
        break;

      case TLV_DATAARG_FINALBLOCKID_PTR:
        arg_ptr = va_arg(vl, name_component_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (data.metainfo.enable_FinalBlockId) {
          *(name_component_t*)arg_ptr = data.metainfo.final_block_id;
        }
        else {
          ((name_component_t*)arg_ptr)->size = 0;
        }
        break;

      case TLV_DATAARG_FINALBLOCKID_BUF:
        finalblockid_ptr = va_arg(vl, uint8_t**);
        if (finalblockid_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *finalblockid_ptr = NULL;
        break;

      case TLV_DATAARG_FINALBLOCKID_U64:
        arg_ptr = va_arg(vl, uint64_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (data.metainfo.enable_FinalBlockId) {
          *(uint64_t*)arg_ptr = tlv_decode_segno(&data.metainfo.final_block_id);
        }
        else {
          *(uint64_t*)arg_ptr = (uint64_t)-1;
        }
        break;

      case TLV_DATAARG_CONTENT_BUF:
        content_ptr = va_arg(vl, uint8_t**);
        if (content_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *content_ptr = NULL;
        break;

      case TLV_DATAARG_CONTENT_SIZE:
        arg_ptr = va_arg(vl, size_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *(size_t*)arg_ptr = (size_t)data.content_size;
        break;

      case TLV_DATAARG_SIGTYPE_U8:
        arg_ptr = va_arg(vl, uint8_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *(uint8_t*)arg_ptr = data.signature.sig_type;
        break;

      case TLV_DATAARG_SIGKEY_PTR:
        key_ptr = va_arg(vl, void*);
        break;

      case TLV_DATAARG_SIGTIME_U64:
        arg_ptr = va_arg(vl, uint64_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (data.signature.enable_Timestamp) {
          *(uint64_t*)arg_ptr = data.signature.timestamp;
        }
        else {
          *(uint64_t*)arg_ptr = 0;
        }

      case TLV_DATAARG_VERIFY:
        verify_sig = va_arg(vl, uint32_t);
        break;

      default:
        ret = NDN_INVALID_ARG;
        break;
    }
  }
  va_end(vl);
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Decode Name (No need to check for NULL since decoding succeeded)
  valptr = tlv_get_type_length(ptr, end - ptr, &block_type, &block_len);
  if (block_type != TLV_Name) {
    return NDN_UNSUPPORTED_FORMAT;
  }
  if (namebuf_ptr != NULL) {
    *namebuf_ptr = ptr;
  }
  ptr = valptr + block_len;

  // Metainfo if applicable
  if (data.metainfo.enable_FinalBlockId && finalblockid_ptr != NULL) {
    valptr = tlv_get_type_length(ptr, end - ptr, &block_type, &block_len);
    if (block_type != TLV_MetaInfo) {
      return NDN_UNSUPPORTED_FORMAT;
    }
    ptr = valptr + block_len;

    while(valptr < ptr) {
      valptr = tlv_get_type_length(valptr, end - valptr, &block_type, &block_len);
      if (block_type == TLV_FinalBlockId) {
        *finalblockid_ptr = valptr;
      }
      valptr += block_len;
    }
  }

  // Content if applicable
  if (content_ptr && data.content_size > 0) {
    do{
      valptr = tlv_get_type_length(ptr, end - ptr, &block_type, &block_len);
      ptr = valptr + block_len;
    }while(block_type != TLV_Content && ptr < end);
    *content_ptr = valptr;
  }

  // Verify if required
  if (verify_sig) {
    switch(data.signature.sig_type) {
      case NDN_SIG_TYPE_DIGEST_SHA256:
        ret = ndn_data_tlv_decode_digest_verify(&data, buf, buflen);
        break;

      case NDN_SIG_TYPE_ECDSA_SHA256:
        if (key_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
        }
        else {
          ret = ndn_data_tlv_decode_ecdsa_verify(&data, buf, buflen, (ndn_ecc_pub_t*)key_ptr);
        }
        break;

      case NDN_SIG_TYPE_HMAC_SHA256:
        if (key_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
        }
        else {
          ret = ndn_data_tlv_decode_hmac_verify(&data, buf, buflen, (ndn_hmac_key_t*)key_ptr);
        }
        break;

      default:
        ret = NDN_SEC_UNSUPPORT_SIGN_TYPE;
        break;
    }
  }

  return ret;
}

int
tlv_make_interest(uint8_t* buf, size_t buflen, size_t* result_size, int argc, ...)
{
  static ndn_interest_t interest;
  ndn_decoder_t decoder;
  ndn_encoder_t encoder;
  va_list vl;
  int i;
  enum TLV_INTARG_TYPE argtype;
  int ret = NDN_SUCCESS;
  void* arg_ptr = NULL;
  uint8_t* params_buf_ptr = NULL;
  ndn_name_t* identity = NULL;
  void* key_ptr = NULL;
  uint64_t segno = (uint64_t)-1;

  ndn_interest_init(&interest);
  va_start(vl, argc);
  for(i = 0; i < argc && ret == NDN_SUCCESS; i ++) {
    argtype = va_arg(vl, int);
    switch(argtype) {
      case TLV_INTARG_NAME_PTR:
        arg_ptr = va_arg(vl, void*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        interest.name = *(ndn_name_t*)arg_ptr;
        break;

      case TLV_INTARG_NAME_BUF:
        arg_ptr = va_arg(vl, void*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        decoder_init(&decoder, (uint8_t*)arg_ptr, INT_MAX);
        ret = ndn_name_tlv_decode(&decoder, &interest.name);
        break;

      case TLV_INTARG_NAME_SEGNO_U64:
        segno = va_arg(vl, uint64_t);
        break;

      case TLV_INTARG_CANBEPREFIX_BOOL:
        ndn_interest_set_CanBePrefix(&interest, va_arg(vl, uint32_t));
        break;

      case TLV_INTARG_MUSTBEFRESH_BOOL:
        ndn_interest_set_MustBeFresh(&interest, va_arg(vl, uint32_t));
        break;

      case TLV_INTARG_LIFETIME_U64:
        interest.lifetime = va_arg(vl, uint64_t);
        break;

      case TLV_INTARG_HOTLIMIT_U8:
        ndn_interest_set_HopLimit(&interest, (uint8_t)va_arg(vl, uint32_t));
        break;

      case TLV_INTARG_PARAMS_BUF:
        params_buf_ptr = va_arg(vl, uint8_t*);
        break;

      case TLV_INTARG_PARAMS_SIZE:
        interest.parameters.size = va_arg(vl, size_t);
        break;

      case TLV_INTARG_SIGTYPE_U8:
        ret = ndn_signature_set_signature_type(&interest.signature, (uint8_t)va_arg(vl, uint32_t));
        BIT_SET(interest.flags, 7);
        break;

      case TLV_INTARG_IDENTITYNAME_PTR:
        identity = va_arg(vl, ndn_name_t*);
        break;

      case TLV_INTARG_SIGKEY_PTR:
        key_ptr = va_arg(vl, void*);
        break;

      default:
        ret = NDN_INVALID_ARG;
        break;
    }
  }
  va_end(vl);
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Copy params
  if (interest.parameters.size > 0 && params_buf_ptr != NULL) {
    ret = ndn_interest_set_Parameters(&interest, params_buf_ptr, interest.parameters.size);
  }
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Check name
  if (interest.name.components_size == 0) {
    return NDN_INVALID_ARG;
  }
  if (segno != (uint64_t)-1) {
    tlv_encode_segno(&interest.name.components[interest.name.components_size], segno);
    interest.name.components_size += 1;
  }

  // Encode
  encoder_init(&encoder, buf, buflen);
  if (ndn_interest_is_signed(&interest)) {
    switch(interest.signature.sig_type) {
      case NDN_SIG_TYPE_DIGEST_SHA256:
        ret = ndn_signed_interest_digest_sign(&interest);
        break;

      case NDN_SIG_TYPE_ECDSA_SHA256:
        if (identity == NULL || key_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
        }
        else {
          ret = ndn_signed_interest_ecdsa_sign(&interest, identity, (ndn_ecc_prv_t*)key_ptr);
        }
        break;

      case NDN_SIG_TYPE_HMAC_SHA256:
        if (identity == NULL || key_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
        }
        else {
          ret = ndn_signed_interest_hmac_sign(&interest, identity, (ndn_hmac_key_t*)key_ptr);
        }
        break;

      default:
        ret = NDN_SEC_UNSUPPORT_SIGN_TYPE;
        break;
    }
  }
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (result_size != NULL) {
    *result_size = encoder.offset;
  }

  return ret;
}

int
tlv_parse_interest(uint8_t* buf, size_t buflen, int argc, ...)
{
  static ndn_interest_t interest;
  va_list vl;
  int i, ret = NDN_SUCCESS;
  enum TLV_INTARG_TYPE argtype;
  uint32_t block_type, block_len;
  uint8_t *ptr, *valptr, *end = buf + buflen;
  uint8_t **namebuf_ptr = NULL;
  uint8_t **params_ptr = NULL;
  void *arg_ptr = NULL;
  void *key_ptr = NULL;
  bool verify_sig = false;

  // Check type and length
  ptr = tlv_get_type_length(buf, buflen, &block_type, &block_len);
  if (ptr == NULL) {
    return NDN_OVERSIZE_VAR;
  }
  if (block_type != TLV_Interest) {
    return NDN_WRONG_TLV_TYPE;
  }
  if (block_len != end - ptr) {
    return NDN_WRONG_TLV_LENGTH;
  }

  // Decode interest
  ret = ndn_interest_from_block(&interest, buf, buflen);
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Parse args
  va_start(vl, argc);
  for (i = 0; i < argc && ret == NDN_SUCCESS; i++) {
    argtype = va_arg(vl, int);
    switch(argtype) {
      case TLV_INTARG_NAME_PTR:
        arg_ptr = va_arg(vl, ndn_name_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *(ndn_name_t*)arg_ptr = interest.name;
        break;

      case TLV_INTARG_NAME_BUF:
        namebuf_ptr = va_arg(vl, uint8_t**);
        if (namebuf_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *namebuf_ptr = NULL;
        break;

      case TLV_INTARG_NAME_SEGNO_U64:
        arg_ptr = va_arg(vl, uint64_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (interest.name.components_size > 0) {
          *(uint64_t*)arg_ptr = tlv_decode_segno(&interest.name.components[interest.name.components_size - 1]);
        }
        else {
          ret = NDN_UNSUPPORTED_FORMAT;
        }
        break;

      case TLV_INTARG_CANBEPREFIX_BOOL:
        arg_ptr = va_arg(vl, bool*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *(bool*)arg_ptr = ndn_interest_get_CanBePrefix(&interest);
        break;

      case TLV_INTARG_MUSTBEFRESH_BOOL:
        arg_ptr = va_arg(vl, bool*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *(bool*)arg_ptr = ndn_interest_get_MustBeFresh(&interest);
        break;

      case TLV_INTARG_LIFETIME_U64:
        arg_ptr = va_arg(vl, uint64_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *(uint64_t*)arg_ptr = interest.lifetime;
        break;

      case TLV_INTARG_HOTLIMIT_U8:
        arg_ptr = va_arg(vl, uint8_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (ndn_interest_has_HopLimit(&interest)) {
          *(uint8_t*)arg_ptr = interest.hop_limit;
        }
        else {
          *(uint8_t*)arg_ptr = 0xFF;
        }
        break;

      case TLV_INTARG_PARAMS_BUF:
        params_ptr = va_arg(vl, uint8_t**);
        if (params_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        *params_ptr = NULL;
        break;

      case TLV_INTARG_PARAMS_SIZE:
        arg_ptr = va_arg(vl, size_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (ndn_interest_has_Parameters(&interest)) {
          *(size_t*)arg_ptr = (size_t)interest.parameters.size;
        }
        else {
          *(size_t*)arg_ptr = 0;
        }
        break;

      case TLV_INTARG_SIGTYPE_U8:
        arg_ptr = va_arg(vl, uint8_t*);
        if (arg_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
          break;
        }
        if (ndn_interest_is_signed(&interest)) {
          *(uint8_t*)arg_ptr = interest.signature.sig_type;
        }
        else {
          *(uint8_t*)arg_ptr = (uint8_t)-1;
        }
        break;

      case TLV_INTARG_SIGKEY_PTR:
        key_ptr = va_arg(vl, void*);
        break;

      case TLV_INTARG_VERIFY:
        verify_sig = va_arg(vl, uint32_t);
        break;

      default:
        ret = NDN_INVALID_ARG;
        break;
    }
  }
  va_end(vl);
  if (ret != NDN_SUCCESS) {
    return ret;
  }

  // Decode Name (No need to check for NULL since decoding succeeded)
  valptr = tlv_get_type_length(ptr, end - ptr, &block_type, &block_len);
  if (block_type != TLV_Name) {
    return NDN_UNSUPPORTED_FORMAT;
  }
  if (namebuf_ptr != NULL) {
    *namebuf_ptr = ptr;
  }
  ptr = valptr + block_len;

  // Content if applicable
  if (params_ptr && ndn_interest_has_Parameters(&interest) && interest.parameters.size > 0) {
    do {
      valptr = tlv_get_type_length(ptr, end - ptr, &block_type, &block_len);
      ptr = valptr + block_len;
    } while (block_type != TLV_ApplicationParameters && ptr < end);
    *params_ptr = valptr;
  }

  // Verify if required
  if (verify_sig && ndn_interest_is_signed(&interest)) {
    switch(interest.signature.sig_type) {
      case NDN_SIG_TYPE_DIGEST_SHA256:
        ret = ndn_signed_interest_digest_verify(&interest);
        break;

      case NDN_SIG_TYPE_ECDSA_SHA256:
        if (key_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
        }
        else {
          ret = ndn_signed_interest_ecdsa_verify(&interest, (ndn_ecc_pub_t*)key_ptr);
        }
        break;

      case NDN_SIG_TYPE_HMAC_SHA256:
        if (key_ptr == NULL) {
          ret = NDN_INVALID_POINTER;
        }
        else {
          ret = ndn_signed_interest_hmac_verify(&interest, (ndn_hmac_key_t*)key_ptr);
        }
        break;

      default:
        ret = NDN_SEC_UNSUPPORT_SIGN_TYPE;
        break;
    }
  }

  return ret;
}
