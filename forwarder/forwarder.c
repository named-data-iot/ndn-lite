/*
 * Copyright (C) 2018 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "forwarder.h"
#include "memory-pool.h"
#include "../encode/name.h"
#include "../encode/data.h"

#include <stdio.h>

static ndn_forwarder_t instance;

ndn_forwarder_t*
ndn_forwarder_get_instance(void)
{
  return &instance;
}

static int
forwarder_multicast_strategy(ndn_face_intf_t* face, ndn_name_t* name,
                             const uint8_t* raw_interest, uint32_t size,
                             const ndn_pit_entry_t* pit_entry);

/************************************************************/
/*  Definition of PIT table APIs                            */
/************************************************************/

static void
pit_table_init(void)
{
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    instance.pit[i].interest_name.components_size = NDN_FWD_INVALID_NAME_SIZE;
  }
}

static ndn_pit_entry_t*
pit_table_find_or_insert(ndn_name_t* name)
{
  // Find
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    if (ndn_name_compare(&instance.pit[i].interest_name, name) == 0) {
      return &instance.pit[i];
    }
  }

  // Insert
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    if (instance.pit[i].interest_name.components_size == NDN_FWD_INVALID_NAME_SIZE) {
      instance.pit[i].interest_name = *name;
      instance.pit[i].incoming_face_size = 0;
      return &instance.pit[i];
    }
  }
  return NULL;
}

/************************************************************/
/*  Definition of FIB table APIs                            */
/************************************************************/

static void
fib_table_init(void)
{
  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    instance.fib[i].name_prefix.components_size = NDN_FWD_INVALID_NAME_SIZE;
  }
}

static ndn_fib_entry_t*
fib_table_find(const ndn_name_t* name)
{
  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    if (ndn_name_is_prefix_of(&instance.fib[i].name_prefix, name) == 0) {
      return &instance.fib[i];
    }
  }
  return NULL;
}

// static ndn_fib_entry_t*
// fib_table_find_by_face(const ndn_face_intf_t* face)
// {
//   for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
//     if (instance.fib[i].name_prefix.components_size != NDN_FWD_INVALID_NAME_SIZE
//         && instance.fib[i].next_hop == face) {
//       return &instance.fib[i];
//     }
//   }
//   return NULL;
// }

/************************************************************/
/*  Definition of forwarder APIs                            */
/************************************************************/

// Send data packet out
static int
ndn_forwarder_on_outgoing_data(ndn_face_intf_t* face, const ndn_name_t* name,
                               const uint8_t* raw_data, uint32_t size)
{
  return ndn_face_send(face, name, raw_data, size);
}

// Send interest packet out
static int
ndn_forwarder_on_outgoing_interest(ndn_face_intf_t* face, const ndn_name_t* name,
                                   const uint8_t* raw_interest, uint32_t size)
{
  return ndn_face_send(face, name, raw_interest, size);
}

ndn_forwarder_t*
ndn_forwarder_init(void)
{
  pit_table_init();
  fib_table_init();
  return &instance;
}

int
ndn_forwarder_fib_insert(const ndn_name_t* name_prefix,
                         ndn_face_intf_t* face, uint8_t cost)
{
  // already exists
  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    if (ndn_name_compare(&instance.fib[i].name_prefix, name_prefix) == 0
        && instance.fib[i].next_hop == face) {
      if (face->state != NDN_FACE_STATE_UP)
        ndn_face_up(face);
      return 0;
    }
  }

  // find an unused fib entry
  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    if (instance.fib[i].name_prefix.components_size == NDN_FWD_INVALID_NAME_SIZE) {
      instance.fib[i].name_prefix = *name_prefix;
      instance.fib[i].next_hop = face;
      instance.fib[i].cost = cost;
      ndn_face_up(face);

      printf("Forwarder: successfully insert FIB\n");

      return 0;
    }
  }
  return NDN_FWD_FIB_FULL;
}

int
ndn_forwarder_on_incoming_data(ndn_forwarder_t* self, ndn_face_intf_t* face, ndn_name_t *name,
                               const uint8_t* raw_data, uint32_t size)
{
  (void)face;
  bool bypass = (name != NULL);

  // If no bypass data, we need to decode it manually
  if (!bypass) {
    // Allocate memory
    name = (ndn_name_t*)ndn_memory_pool_alloc();
    if (!name) {
      return NDN_FWD_INSUFFICIENT_MEMORY;
    }
    // Decode name only
    ndn_decoder_t decoder;
    uint32_t probe = 0;
    int ret = 0;
    decoder_init(&decoder, raw_data, size);
    ret = decoder_get_type(&decoder, &probe);
    ret = decoder_get_length(&decoder, &probe);
    ret = ndn_name_tlv_decode(&decoder, name);
    if (ret < 0) {
      ndn_memory_pool_free(name);
      return ret;
    }
  }

  // Match with pit
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    if (ndn_name_compare(&self->pit[i].interest_name, name) == 0) {
      // Send out data
      for (uint8_t j = 0; j < self->pit[i].incoming_face_size; j++) {
        ndn_forwarder_on_outgoing_data(self->pit[i].incoming_face[j], name, raw_data, size);
      }
      // Delete PIT Entry
      pit_entry_delete(&self->pit[i]);
      break;
    }
  }

  // Free memory
  if (!bypass) {
    ndn_memory_pool_free(name);
  }

  return 0;
}

int
ndn_forwarder_on_incoming_interest(ndn_forwarder_t* self, ndn_face_intf_t* face, ndn_name_t* name,
                                   const uint8_t* raw_interest, uint32_t size)
{
  printf("Forwarder: on Interest\n");

  (void)self;
  int ret = 0;
  bool bypass = (name != NULL);

  // If no bypass interest, we need to decode it manually
  if (!bypass) {
    // Allocate memory
    // A name is expensive, don't want to do it on stack
    name = (ndn_name_t*)ndn_memory_pool_alloc();
    if (!name) {
      return NDN_FWD_INSUFFICIENT_MEMORY;
    }

    // Decode name only
    uint32_t probe = 0;
    ndn_decoder_t decoder;
    decoder_init(&decoder, raw_interest, size);
    ret = decoder_get_type(&decoder, &probe);
    ret = decoder_get_length(&decoder, &probe);
    ret = ndn_name_tlv_decode(&decoder, name);
    if (ret != 0) {
      ndn_memory_pool_free(name);
      return ret;
    }
  }

  // Insert into PIT
  ndn_pit_entry_t* pit_entry = pit_table_find_or_insert(name);
  if (pit_entry == NULL) {
    if (!bypass) {
      ndn_memory_pool_free(name);
    }
    return NDN_FWD_PIT_FULL;
  }
  pit_entry_add_incoming_face(pit_entry, face);

  // Multicast Strategy
  ret = forwarder_multicast_strategy(face, name, raw_interest, size, pit_entry);

  // Reject PIT
  if (ret != 0) {
    pit_entry_delete(pit_entry);
  }

  // Free memory
  if (!bypass) {
    ndn_memory_pool_free(name);
  }

  return ret;
}

static int
forwarder_multicast_strategy(ndn_face_intf_t* face, ndn_name_t* name,
                             const uint8_t* raw_interest, uint32_t size,
                             const ndn_pit_entry_t* pit_entry)
{
  (void)pit_entry;
  ndn_fib_entry_t* fib_entry;
  fib_entry = fib_table_find(name);
  if (fib_entry && fib_entry->next_hop && fib_entry->next_hop != face) {
    ndn_forwarder_on_outgoing_interest(fib_entry->next_hop, name, raw_interest, size);
  }
  else {
    // TODO: Send Nack
    return NDN_FWD_INTEREST_REJECTED;
  }
  return 0;
}
