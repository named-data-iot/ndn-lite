#include "name.h"
#include <stdio.h>

int
name_component_from_block(name_component_t* component, name_component_block_t* block)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block->value, block->size);
  decoder_get_type(&decoder, &component->type);
  decoder_get_length(&decoder, &component->size);
  decoder_get_raw_buffer_value(&decoder, component->value, component->size);
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
name_component_tlv_encode(name_component_t* component, name_component_block_t* output)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, output->value, NAME_COMPONENT_BLOCK_SIZE);
  encoder_append_type(&encoder, component->type);
  encoder_append_length(&encoder, component->size);
  encoder_append_raw_buffer_value(&encoder, component->value, component->size);
  output->size = encoder.offset;
  return 0;
}


int
ndn_name_init(ndn_name_t *name, name_component_t* components, uint32_t size)
{
  if (size <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(name->components, components, size * sizeof(name_component_t));
    name->components_size = size;
    return 0;
  }
  else
    return -1;
}

int
ndn_name_append_component(ndn_name_t *name, name_component_t* component)
{
  if (name->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(name->components + name->components_size, component, sizeof(name_component_t));
    name->components_size++;
    return 0;
  }
  else
    return -1;
}

int
ndn_name_tlv_encode(ndn_name_t *name, ndn_block_t* output)
{
  int block_sizes[name->components_size];

  ndn_encoder_t encoder;
  encoder_init(&encoder, output->value, output->size);
  encoder_append_type(&encoder, TLV_Name);
  size_t value_size = 0;
  for (size_t i = 0; i < name->components_size; i++) {
    block_sizes[i] = name_component_probe_block_size(&name->components[i]);
    value_size += block_sizes[i];
  }
  encoder_append_length(&encoder, value_size);

  for (size_t i = 0; i < name->components_size; i++) {
    name_component_block_t comp_block;
    name_component_tlv_encode(&name->components[i], &comp_block);
    int result = encoder_append_raw_buffer_value(&encoder, comp_block.value, comp_block.size);
    if (result < 0)
      return result;
  }
  return 0;
}
