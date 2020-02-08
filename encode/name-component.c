/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "name-component.h"
#include <stdio.h>

int
_init_component_from_uint_value(name_component_t* component, uint64_t value)
{
  component->size = encoder_probe_uint_length(value);
  ndn_encoder_t encoder;
  encoder_init(&encoder, component->value, NDN_NAME_COMPONENT_BUFFER_SIZE);
  return encoder_append_uint_value(&encoder, value);
}

uint64_t
_turn_component_to_uint_value(const name_component_t* component)
{
  uint64_t result;
  ndn_decoder_t decoder;
  decoder_init(&decoder, component->value, NDN_NAME_COMPONENT_BUFFER_SIZE);
  decoder_get_uint_value(&decoder, component->size, &result);
  return result;
}

int
name_component_from_string(name_component_t* component, const char* string, uint32_t size)
{
  int starting = 0;
  int length = size;
  if (string[starting] == '/') {
    starting = 1;
  }
  if (string[length - 1] == '\0') {
    length -= 1;
  }
  return name_component_from_buffer(component, TLV_GenericNameComponent, (const uint8_t*)string + starting, length);
}

int
name_component_from_timestamp(name_component_t* component, ndn_time_us_t timestamp)
{
  component->type = TLV_TimestampNameComponent;
  return _init_component_from_uint_value(component, timestamp);
}

ndn_time_us_t
name_component_to_timestamp(const name_component_t* component)
{
  if (component->type == TLV_TimestampNameComponent) return _turn_component_to_uint_value(component);
  else return 0;
}

int
name_component_from_version(name_component_t* component, uint64_t version)
{
  component->type = TLV_VersionNameComponent;
  return _init_component_from_uint_value(component, version);
}

uint64_t
name_component_to_version(const name_component_t* component)
{
  if (component->type == TLV_VersionNameComponent) return _turn_component_to_uint_value(component);
  else return 0;
}

int
name_component_from_segment_num(name_component_t* component, uint64_t segment_num)
{
  component->type = TLV_SegmentNameComponent;
  return _init_component_from_uint_value(component, segment_num);
}

uint64_t
name_component_to_segment_num(const name_component_t* component)
{
  if (component->type == TLV_SegmentNameComponent) return _turn_component_to_uint_value(component);
  else return 0;
}

int
name_component_from_sequence_num(name_component_t* component, uint64_t sequence)
{
  component->type = TLV_SequenceNumNameComponent;
  return _init_component_from_uint_value(component, sequence);
}

uint64_t
name_component_to_sequence_num(const name_component_t* component)
{
  if (component->type == TLV_SequenceNumNameComponent) return _turn_component_to_uint_value(component);
  else return 0;
}

int
name_component_tlv_decode(ndn_decoder_t* decoder, name_component_t* component)
{
  int ret_val = -1;
  uint32_t probe = 0;
  ret_val = decoder_get_type(decoder, &component->type);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (!(component->type == TLV_GenericNameComponent
        || component->type == TLV_ImplicitSha256DigestComponent
        || component->type == TLV_ParametersSha256DigestComponent
        || component->type == TLV_KeywordNameComponent
        || component->type == TLV_SegmentNameComponent
        || component->type == TLV_ByteOffsetNameComponent
        || component->type == TLV_VersionNameComponent
        || component->type == TLV_TimestampNameComponent
        || component->type == TLV_SegmentNameComponent)) {
    return NDN_WRONG_TLV_TYPE;
  }
  ret_val = decoder_get_length(decoder, &probe);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (probe > NDN_NAME_COMPONENT_BUFFER_SIZE) {
    return NDN_OVERSIZE;
  }
  component->size = probe;
  return decoder_get_raw_buffer_value(decoder, component->value, component->size);
}

int
name_component_from_block(name_component_t* component, const uint8_t* value, uint32_t size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, value, size);
  return name_component_tlv_decode(&decoder, component);
}

int
name_component_compare(const name_component_t* lhs, const name_component_t* rhs)
{
  if (lhs->type != rhs->type) return -1;
  if (lhs->size != rhs->size) return -1;
  int result = memcmp(lhs->value, rhs->value, lhs->size);
  if (result != 0) return -1;
  else return 0;
}

int
name_component_tlv_encode(ndn_encoder_t* encoder, const name_component_t* component)
{
  int ret_val = -1;
  ret_val = encoder_append_type(encoder, component->type);
  if (ret_val != NDN_SUCCESS) return ret_val;
  ret_val = encoder_append_length(encoder, component->size);
  if (ret_val != NDN_SUCCESS) return ret_val;
  return encoder_append_raw_buffer_value(encoder, component->value, component->size);
}

void
name_component_print(const name_component_t* component)
{
  switch (component->type) {
    case TLV_ImplicitSha256DigestComponent:
      printf("/sha256digiest=0x");
      for (int j = 0; j < component->size; j++) {
        printf("%02x", component->value[j]);
      }
      break;

    case TLV_ParametersSha256DigestComponent:
      printf("/params-sha256=0x");
      for (int j = 0; j < component->size; j++) {
        printf("%02x", component->value[j]);
      }
      break;

    case TLV_VersionNameComponent:
      printf("/v=%llu", name_component_to_version(component));
      break;

    case TLV_TimestampNameComponent:
      printf("/t=%llu", name_component_to_timestamp(component));
      break;

    case TLV_SequenceNumNameComponent:
      printf("/seq=%llu", name_component_to_sequence_num(component));
      break;

    default:
      printf("/");
      for (int j = 0; j < component->size; j++) {
        if (component->value[j] >= 33 && component->value[j] < 126) {
          printf("%c", component->value[j]);
        }
        else {
          printf("0x%02x", component->value[j]);
        }
      }
      break;
  }
}