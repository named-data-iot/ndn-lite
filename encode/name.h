#ifndef ENCODING_NAME_H
#define ENCODING_NAME_H

#include "tlv.h"
#include "encoder.h"
#include "decoder.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct name_component {
  uint32_t type;
  uint8_t* value;
  size_t size;
} name_component_t;

typedef struct ndn_name {
  name_component_t* components;
  size_t component_size;
} ndn_name_t;

// the function will NOT do memory copy (hard copy)
static inline name_component_t
name_component_from_buffer(uint32_t type, uint8_t* value, size_t size)
{
  name_component_t component;
  component.type = type;
  component.value = value;
  component.size = size;
  return component;
}

// the function will NOT do memory copy (hard copy)
static inline name_component_t
name_component_from_string(char* string, size_t size)
{
  return name_component_from_buffer(TLV_GenericNameComponent, (uint8_t*)string, size);
}

// the function will do memory copy (hard copy)
// the component must already have been initialized with proper-size uint8_t*
// use function decoder_probe_value_size to get it
int
name_component_from_block(name_component_t* component, ndn_block_t* block);

// return 0 if two components are the same
int
name_component_compare(name_component_t* a, name_component_t* b);

static inline int
name_component_block_size(name_component_t* component)
{
  return encoder_probe_block_size(component->type, component->size);
}

// use name_component_block_size function to get the exact block size and
// create an ndn_block_t
int
name_component_wire_encode(name_component_t* component, ndn_block_t* output);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NAME_H
