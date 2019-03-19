/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name-light.h"

 /************************/
 /*  Helper Functions    */
 /************************/

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


/************************/
/*  Interfaces          */
/************************/
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
