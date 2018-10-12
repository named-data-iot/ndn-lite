#include "name.h"

int
name_component_from_block(name_component_t* component, ndn_block_t* block)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block);
  decoder_get_type(&decoder, &component.type);
  uint32_t buffer_size;
  decoder_get_length(&decoder, &buffer_size);
  uint8_t buffer_value[buffer_size];
  ndn_buffer_t buffer;
  buffer.value = buffer_value;
  buffer.size = buffer_size;
  decoder_get_buffer_value(&decoder, &buffer);
  component.component_buffer = &buffer;
}

int
name_component_compare(const name_component_t* a, name_component_t* b)
{
  if (a == NULL || b == NULL) return -2;
  if (a->type != b->type) return -1;
  if (a->component_buffer.size != b->component_buffer.size) return -1;
  else {
    int result = memcmp(a->component_buffer.value, b->component_buffer.value, a->component_buffer.size);
    if (n != 0) return -1;
    else return 0;
  }
}
