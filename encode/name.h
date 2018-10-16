#ifndef ENCODING_NAME_H
#define ENCODING_NAME_H

#include "tlv.h"
#include "encoder.h"
#include "decoder.h"
#include "ndn_constants.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct name_component {
  uint32_t type;
  uint8_t value[NAME_COMPONENT_BUFFER_SIZE];
  uint32_t size;
} name_component_t;

typedef struct name_component_block {
  uint8_t value[NAME_COMPONENT_BLOCK_SIZE];
  uint32_t size;
} name_component_block_t;

typedef struct ndn_name {
  name_component_t components[NDN_NAME_COMPONENTS_SIZE];
  uint32_t components_size;
} ndn_name_t;

// the function will do memory copy
static inline int
name_component_from_buffer(name_component_t* component, uint32_t type, uint8_t* value, uint32_t size)
{
  if (size > NAME_COMPONENT_BUFFER_SIZE)
    return NDN_ERROR_OVERSIZE;
  component->type = type;
  memcpy(component->value, value, size);
  component->size = size;
  return 0;
}

// the function will do memory copy
static inline int
name_component_from_string(name_component_t* component, char* string, uint32_t size)
{
  return name_component_from_buffer(component, TLV_GenericNameComponent, (uint8_t*)string, size);
}

// the function will do memory copy
// the component must already have been initialized with proper-size uint8_t*
// use function decoder_probe_value_size to get it
int
name_component_from_block(name_component_t* component, name_component_block_t* block);

// return 0 if two components are the same
int
name_component_compare(name_component_t* a, name_component_t* b);

static inline int
name_component_probe_block_size(name_component_t* component)
{
  return encoder_probe_block_size(component->type, component->size);
}

int
name_component_tlv_encode(name_component_t* component, name_component_block_t* output);

// will do memory copy
int
ndn_name_init(ndn_name_t *name, name_component_t* components, uint32_t size);

// will do memory copy
int
ndn_name_append_component(ndn_name_t *name, name_component_t* component);

static inline uint32_t
ndn_name_probe_block_size(ndn_name_t *name)
{
  uint32_t value_size = 0;
  for (uint32_t i = 0; i < name->components_size; i++) {
    value_size += name_component_probe_block_size(&name->components[i]);
  }
  return encoder_probe_block_size(TLV_Name, value_size);
}

// will do memory copy
// need to call ndn_name_probe_block_size to initialize output block in advance
int
ndn_name_tlv_encode(ndn_name_t *name, ndn_block_t* output);

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NAME_H
