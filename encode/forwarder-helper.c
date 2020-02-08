/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

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

uint64_t
tlv_get_uint(uint8_t* buf, size_t buflen)
{
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
  if (ptr == NULL) {
    return NDN_OVERSIZE_VAR;
  }
  if (real_type != TLV_Interest) {
    return NDN_WRONG_TLV_TYPE;
  }
  if (real_len != buflen - (ptr - interest)) {
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
  while (ptr < interest + buflen) {
    ptr = tlv_get_type_length(ptr, buflen - (ptr - interest), &real_type, &real_len);
    if(ptr == NULL){
      return NDN_OVERSIZE_VAR;
    }
    if (real_type == TLV_CanBePrefix) {
      options->can_be_prefix = true;
    }
    else if (real_type == TLV_MustBeFresh) {
      options->must_be_fresh = true;
    }
    else if (real_type == TLV_HopLimit && real_len == sizeof(options->hop_limit)) {
      options->hop_limit = *ptr;
    }
    else if (real_type == TLV_Nonce && real_len == sizeof(options->nonce)) {
      memcpy(&options->nonce, ptr, sizeof(options->nonce));
    }
    else if (real_type == TLV_InterestLifetime) {
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
