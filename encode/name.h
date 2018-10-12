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
  ndn_buffer_t component_buffer;
} name_component_t;

typedef struct ndn_name {
  name_component_t* components;
  size_t component_size;
} ndn_name_t;

// the function will NOT do memory copy (hard copy)
static inline void
name_component_from_buffer(name_component_t* component, uint32_t type, ndn_buffer_t* buffer)
{
  component.type = type;
  component.component_buffer = buffer;
}

// the function will NOT do memory copy (hard copy)
static inline void
name_component_from_string(name_component_t* component, char* string)
{
  ndn_buffer_t buffer;
  buffer.value = (uint8_t*)string;
  buffer.size = sizeof(string);
  name_component_from_buffer(component, TLV_GenericNameComponent, &buffer);
}

// the function will do memory copy (hard copy)
int
name_component_from_block(name_component_t* component, ndn_block_t* block);

// return 0 if two components are the same
int
name_component_compare(const name_component_t* a, name_component_t* b);

static inline int
name_component_block_size(name_component_t* component)
{
  return encoder_probe_block_size(component.type, component.component_buffer.size);
}

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NAME_H
