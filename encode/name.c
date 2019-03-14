/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name.h"

int
ndn_name_init(ndn_name_t *name, const name_component_t* components, uint32_t size)
{
  if (size <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(name->components, components, size * sizeof(name_component_t));
    name->components_size = size;
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

int
ndn_name_tlv_decode(ndn_decoder_t* decoder, ndn_name_t* name)
{

  int ret_val = -1;

  uint32_t type = 0;
  ret_val = decoder_get_type(decoder, &type);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (type != TLV_Name) {
    return NDN_WRONG_TLV_TYPE;
  }
  uint32_t length = 0;
  ret_val = decoder_get_length(decoder, &length);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t start_offset = decoder->offset;
  int counter = 0;
  while (decoder->offset < start_offset + length) {
    if (counter >= NDN_NAME_COMPONENTS_SIZE)
      return NDN_OVERSIZE;
    int result = name_component_tlv_decode(decoder, &name->components[counter]);
    if (result < 0)
      return result;
    ++counter;
  }
  name->components_size = counter;
  return 0;
}

int
ndn_name_from_block(ndn_name_t* name, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  return ndn_name_tlv_decode(&decoder, name);
}

int
ndn_name_append_component(ndn_name_t *name, const name_component_t* component)
{
  if (name->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(name->components + name->components_size, component, sizeof(name_component_t));
    name->components_size++;
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

int
ndn_name_from_string(ndn_name_t *name, const char* string, uint32_t size)
{

  int ret_val = -1;

  name->components_size = 0;

  uint32_t i = 0;
  uint32_t last_divider = 0;
  if (string[i] != '/') {
    return NDN_NAME_INVALID_FORMAT;
  }
  ++i;
  while (i < size) {
    if (string[i] == '/') {
      name_component_t component;
      ret_val = name_component_from_string(&component, &string[last_divider + 1], i - last_divider - 1);
      if (ret_val != NDN_SUCCESS) return ret_val;
      int result = ndn_name_append_component(name, &component);
      if (result < 0) {
        return result;
      }
      last_divider = i;
    }
    if (i == size - 1) {
      name_component_t component;
      ret_val = name_component_from_string(&component, &string[last_divider + 1], i - last_divider);
      if (ret_val != NDN_SUCCESS) return ret_val;
      int result = ndn_name_append_component(name, &component);
      if (result < 0) {
        return result;
      }
    }
    ++i;
  }
  return 0;
}

int
ndn_name_tlv_encode(ndn_encoder_t* encoder, const ndn_name_t *name)
{

  int ret_val = -1;

  int block_sizes[name->components_size];
  ret_val = encoder_append_type(encoder, TLV_Name);
  if (ret_val != NDN_SUCCESS) return ret_val;
  size_t value_size = 0;
  for (size_t i = 0; i < name->components_size; i++) {
    block_sizes[i] = name_component_probe_block_size(&name->components[i]);
    value_size += block_sizes[i];
  }
  ret_val = encoder_append_length(encoder, value_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  for (size_t i = 0; i < name->components_size; i++) {
    int result = name_component_tlv_encode(encoder, &name->components[i]);
    if (result < 0)
      return result;
  }
  return 0;
}

int
ndn_name_compare(const ndn_name_t* lhs, const ndn_name_t* rhs)
{
  if (lhs->components_size != rhs->components_size) return -1;
  else {
    int result = 0;
    for (uint8_t i = 0; i < lhs->components_size; i++) {
      result = name_component_compare(&lhs->components[i], &rhs->components[i]);
      if (result != 0) return -1;
    }
    return 0;
  }
}

int
ndn_name_compare_sub_names(const ndn_name_t* lhs, int lhs_b, int lhs_e,
			   const ndn_name_t* rhs, int rhs_b, int rhs_e) {
  if (lhs_e-lhs_b != rhs_e-rhs_b) return -1;
  else {
    int result = 0;
    for (uint8_t i = 0; i < lhs_e-lhs_b; i++) {
      result = name_component_compare(&lhs->components[lhs_b+i], &rhs->components[rhs_b+i]);
      if (result != 0) return -1;
    }
    return 0;
  }
}

int
ndn_name_is_prefix_of(const ndn_name_t* lhs, const ndn_name_t* rhs)
{
  int result = 0;
  uint8_t i;

  if (lhs->components_size > rhs->components_size) {
    return 1;
  }
  else {
    result = 0;
    for (i = 0; i < lhs->components_size; i++) {
      result = name_component_compare(&lhs->components[i], &rhs->components[i]);
      if (result != 0) return 1;
    }
    return 0;
  }
}

int
ndn_name_compare_block(ndn_decoder_t* lhs_decoder, ndn_decoder_t* rhs_decoder)
{
  if (lhs_decoder->input_value == NULL || lhs_decoder->input_size <= 0)
    return NDN_OVERSIZE;
  if (rhs_decoder->input_value == NULL || rhs_decoder->input_size <= 0)
    return NDN_OVERSIZE;

  uint32_t probe = 0;
  uint32_t lhs_name_buffer_length, rhs_name_buffer_length = 0;
  int retval = -1;

  /* check left name type */
  decoder_get_type(lhs_decoder, &probe);
  if (probe != TLV_Name) return NDN_WRONG_TLV_TYPE;

  /* check right name type */
  decoder_get_type(rhs_decoder, &probe);
  if (probe != TLV_Name) return NDN_WRONG_TLV_TYPE;

  /* read left name length */
  retval = decoder_get_length(lhs_decoder, &lhs_name_buffer_length);
  if (retval != NDN_SUCCESS) return NDN_WRONG_TLV_LENGTH;

  /* read right name length */
  retval = decoder_get_length(rhs_decoder, &rhs_name_buffer_length);
  if (retval != NDN_SUCCESS) return NDN_WRONG_TLV_LENGTH;

  int r = memcmp(lhs_decoder->input_value + lhs_decoder->offset,
                 rhs_decoder->input_value + rhs_decoder->offset,
                 lhs_name_buffer_length < rhs_name_buffer_length ?
                 lhs_name_buffer_length : rhs_name_buffer_length);

  if (r < 0) return -1;
  else if (r > 0) return 1;
  else {
      if (lhs_name_buffer_length < rhs_name_buffer_length)
        return -2;
      else if (lhs_name_buffer_length > rhs_name_buffer_length)
             return 2;
      else return 0;
  }
}

/************************************************************/
/*  Ultra Lightweight Encoding Functions                    */
/************************************************************/

static inline int _check_hex(char c)
{
  if ((c >= 'a' && c <= 'f') ||
      (c >= 'A' && c <= 'F') ||
      (c >= '0' && c <= '9'))
    return 1;
  else
    return 0;
}

static inline uint8_t _hex_to_num(char c)
{
  if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
  else {
    switch (c) {
      case 'a':
      case 'A':
        return 10;

      case 'b':
      case 'B':
        return 11;

      case 'c':
      case 'C':
        return 12;

      case 'd':
      case 'D':
        return 13;

      case 'e':
      case 'E':
        return 14;

      case 'f':
      case 'F':
        return 15;

      default:
        break;
    }
    return 0;
  }
}

int
ndn_name_uri_tlv_probe_size(const char* uri, uint32_t len)
{
  if (uri == NULL || len <= 0) return NDN_OVERSIZE;
  if (uri[0] != '/') return NDN_OVERSIZE;  //TODO: support "ndn:" scheme identifier

  // calculate total length & check validity
  uint32_t i = 1;
  uint32_t cl = 0;   // length of all TLV-encoded components
  uint32_t cpl = 0;  // length of current component
  while (i < len) {
    if (uri[i] == '/') {
      // found next slash
      if (cpl == 0) return NDN_OVERSIZE; // empty component
      cl += encoder_probe_block_size(TLV_GenericNameComponent, cpl);
      cpl = 0; // clear current component length
      ++i; // move past the next slash
    }
    else if (uri[i] == '%') {
      // check hex-encoded byte
      if (i + 2 >= len) return NDN_OVERSIZE; // incomplete hex encoding
      if (_check_hex(uri[i+1]) == 0 || _check_hex(uri[i+2]) == 0)
        return NDN_OVERSIZE; // invalid hex encoding
      ++cpl;
      i += 3;
    }
    else {
      // single byte
      ++cpl;
      ++i;
    }
  }

  if (cpl > 0)  // count last (non-empty) component
    cl += encoder_probe_block_size(TLV_GenericNameComponent, cpl);

  // check encoder memory size
  return cl + 1 + encoder_get_var_size(cl);
}

int
ndn_name_uri_tlv_encode(ndn_encoder_t* encoder, const char* uri, uint32_t len)
{
  if (encoder == NULL || uri == NULL || len <= 0) return NDN_OVERSIZE;
  if (uri[0] != '/') return NDN_OVERSIZE;  //TODO: support "ndn:" scheme identifier

  // calculate total length & check validity
  uint32_t i = 1;
  uint32_t cl = 0;   // length of all TLV-encoded components
  uint32_t cpl = 0;  // length of current component
  while (i < len) {
    if (uri[i] == '/') {
      // found next slash
      if (cpl == 0) return NDN_OVERSIZE; // empty component
        cl += encoder_probe_block_size(TLV_GenericNameComponent, cpl);
      cpl = 0; // clear current component length
      ++i; // move past the next slash
    }
    else if (uri[i] == '%') {
      // check hex-encoded byte
      if (i + 2 >= len) return NDN_OVERSIZE; // incomplete hex encoding
      if (_check_hex(uri[i+1]) == 0 || _check_hex(uri[i+2]) == 0)
        return NDN_OVERSIZE; // invalid hex encoding

      ++cpl;
      i += 3;
    }
    else {
      // single byte
      ++cpl;
      ++i;
    }
  }

  if (cpl > 0)  // count last (non-empty) component
    cl += encoder_probe_block_size(TLV_GenericNameComponent, cpl);

  // check encoder memory size
  uint32_t name_len = cl + 1 + encoder_get_var_size(cl);
  if (name_len > (encoder->output_max_size - encoder->offset))
    return NDN_OVERSIZE;

  // start encoding
  encoder_append_type(encoder, TLV_Name);
  encoder_append_length(encoder, cl);

  // encode each component
  i = 1;
  uint32_t j = 1;  // position of the beginning of current component
  cpl = 0;  // length of current component
  while (i <= len) {
    if (i == len && cpl == 0)  // ignore last trailing slash
      break;

    if ((i == len && cpl > 0) || uri[i] == '/') {
      // encode type
      encoder_append_type(encoder, TLV_GenericNameComponent);
      // encode length
      encoder_append_length(encoder, cpl);

      // encode value
      uint32_t k = j;
      while (k < i) {
        if (uri[k] == '%') {
          encoder_append_byte_value(encoder, (_hex_to_num(uri[k+1]) << 4)
                                             + _hex_to_num(uri[k+2]));
          k += 3;
        }
        else {
          encoder_append_byte_value(encoder, (uint8_t)uri[k]);
          k += 1;
        }
      }
      cpl = 0; // clear current component length
      ++i; // move past the next slash
      j = i; // mark beginning of next component
    }
    else if (uri[i] == '%') {
      ++cpl;
      i += 3;
    }
    else {
      // single byte
      ++cpl;
      ++i;
    }
  }
  return NDN_SUCCESS;
}

static inline int _need_escape(uint8_t c)
{
  if ((c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') ||
       c == '+' || c == '.' || c == '_' || c == '-')
    return 0;
  else
    return 1;
}

void ndn_name_print(ndn_decoder_t* decoder)
{
  uint32_t probe = 0;

  /* read name type */
  decoder_get_type(decoder, &probe);

  /* read and ignore name length */
  decoder_get_length(decoder, &probe);

  while (decoder->offset > 0) {
    decoder_get_type(decoder, &probe);
    if (probe != TLV_GenericNameComponent)
      return;

  /* read name component length */
  decoder_get_length(decoder, &probe);
  putchar('/');
  for (int i = 0; i < (int)probe; ++i) {
    if (_need_escape(decoder->input_value[decoder->offset + i]) == 0)
      printf("%c", decoder->input_value[decoder->offset + i]);
    else
      printf("%%%02X", decoder->input_value[decoder->offset + i]);
  }
  decoder_move_forward(decoder, probe);
  }
}
