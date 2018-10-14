#include "name.h"
#include <string.h>

int
name_component_from_block(name_component_t* component, ndn_block_t* block)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block);
  decoder_get_type(&decoder, &component->type);
  uint32_t buffer_size;
  decoder_get_length(&decoder, &buffer_size);
  ndn_buffer_t buffer;
  buffer.value = component->value;
  buffer.size = component->size;
  decoder_get_buffer_value(&decoder, &buffer);
  return 0;
}

int
name_component_compare(name_component_t* a, name_component_t* b)
{
  if (a->type != b->type) return -1;
  if (a->size != b->size) return -1;
  else {
    int result = memcmp(a->value, b->value, a->size);
    if (result != 0) return -1;
    else return 0;
  }
}

int
name_component_wire_encode(name_component_t* component, ndn_block_t* output)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, output);
  encoder_append_type(&encoder, component->type);
  encoder_append_length(&encoder, component->size);

  ndn_buffer_t buffer;
  buffer.value = component->value;
  buffer.size = component->size;
  encoder_append_buffer_value(&encoder, &buffer);
  return 0;
}
