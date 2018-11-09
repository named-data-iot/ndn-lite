/*
 * Copyright (C) 2018 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "forwarder.h"
#include "../encode/name.h"
#include "../encode/data.h"
#include "memory-pool.h"
#include "error_code.h"

// NOTE: Change the implementation if necessary
// This is only used for test.
static ndn_forwarder_t instance;

// NOTE: As is discussed, the main loop of forwarder should be in adapter.
// So the instance may also depend on the platform.
// It is expected to be a singleton in embedded environment, I think.
// Maybe we can make it weak to link, or in the adapter.
ndn_forwarder_t*
forwarder_get_instance()
{
  return &instance;
}

static int
forwarder_multicast_strategy(ndn_forwarder_t* self, ndn_face_t* face, ndn_name_t* name,
                             const uint8_t* raw_interest, uint32_t size,
                             const ndn_pit_entry_t* pit_entry);

//////////////////////

// Send data packet out
static inline int
forwarder_on_outgoing_data(ndn_forwarder_t* self, ndn_face_t* face,
                           const uint8_t* raw_data, uint32_t size)
{
  // TODO Do we need to care mtu and fragment?
  return ndn_face_send(face, raw_data, size);
}

// Send interest packet out
static inline int
forwarder_on_outgoing_interest(ndn_forwarder_t* self, ndn_face_t* face,
                               const uint8_t* raw_interest, uint32_t size)
{
  return ndn_face_send(face, raw_interest, size);
}

int
forwarder_on_incoming_data(ndn_forwarder_t* self, ndn_face_t* face, ndn_name_t *name,
                           const uint8_t* raw_data, uint32_t size)
{
  ndn_pit_entry_t *pit_entry;
  int ret, i;
  bool bypass = (name != NULL);
  ndn_decoder_t decoder;
  uint32_t probe;
  
  // If no bypass data, we need to decode it manually
  if(!bypass) {
    // Allocate memory
    // A name is expensive, don't want to do it on stack
    name = (ndn_name_t*)ndn_memory_pool_alloc();
    if(!name) {
      return NDN_FWD_ERROR_INSUFFICIENT_MEMORY;
    }
    
    // Decode name only
    ret = 0;
    decoder_init(&decoder, raw_data, size);
    ret = decoder_get_type(&decoder, &probe);
    if(ret == 0){
      // ASSERT(probe == TLV_Data);
    }
    if(ret == 0) {
      ret = decoder_get_length(&decoder, &probe);
    }
    if(ret == 0) {
      ret = ndn_name_tlv_decode(&decoder, name);
    }
    if(ret < 0) {
      ndn_memory_pool_free(name);
      return ret;
    }
  }
  
  // Match with pit
  for(pit_entry = pit_first_match(&self->pit, name);
      pit_entry;
      pit_entry = pit_next_match(&self->pit, name, pit_entry)) {
    if(ndn_name_compare(&pit_entry->interest_name, name) == 0) {
      // Send out data
      for(i = 0; i < pit_entry->incoming_face_size; i ++) {
        if(pit_entry->incoming_face[i] == face) {
          continue;
        }
        // TODO: We ignored any error here currently.
        forwarder_on_outgoing_data(self, pit_entry->incoming_face[i], raw_data, size);
      }
      
      // Delete PIT Entry
      pit_entry = pit_delete(&self->pit, pit_entry);
    }
  }
  
  // Free memory
  if(!bypass) {
    ndn_memory_pool_free(name);
  }
  
  return 0;
}

int
forwarder_on_incoming_interest(ndn_forwarder_t* self, ndn_face_t* face, ndn_name_t *name,
                               const uint8_t* raw_interest, uint32_t size)
{
  ndn_pit_entry_t *pit_entry;
  int ret;
  bool bypass = (name != NULL);
  ndn_decoder_t decoder;
  uint32_t probe;

  // If no bypass interest, we need to decode it manually
  if(!bypass) {
    // Allocate memory
    // A name is expensive, don't want to do it on stack
    name = (ndn_name_t*)ndn_memory_pool_alloc();
    if(!name) {
      return NDN_FWD_ERROR_INSUFFICIENT_MEMORY;
    }
    
    // Decode name only
    ret = 0;
    decoder_init(&decoder, raw_interest, size);
    ret = decoder_get_type(&decoder, &probe);
    if(ret == 0){
      // ASSERT(probe == TLV_Interest);
    }
    if(ret == 0) {
      ret = decoder_get_length(&decoder, &probe);
    }
    if(ret == 0) {
      ret = ndn_name_tlv_decode(&decoder, name);
    }
    if(ret < 0) {
      ndn_memory_pool_free(name);
      return ret;
    }
  }

  // Insert into PIT
  pit_entry = pit_find_or_insert(&self->pit, name);
  if(!pit_entry || !pit_add_incoming_face(pit_entry, face)) {
    if(!bypass) {
      ndn_memory_pool_free(name);
    }
    return NDN_FWD_ERROR_PIT_FULL;
  }
  
  // Multicast Strategy
  ret = forwarder_multicast_strategy(self, face, name, raw_interest, size, pit_entry);
  
  // Reject PIT
  if(ret != 0) {
    pit_delete(&self->pit, pit_entry);
  }

  // Free memory
  if(!bypass) {
    ndn_memory_pool_free(name);
  }

  return ret;
}

static int
forwarder_multicast_strategy(ndn_forwarder_t* self, ndn_face_t* face, ndn_name_t* name,
                             const uint8_t* raw_interest, uint32_t size,
                             const ndn_pit_entry_t* pit_entry)
{
  ndn_fib_entry_t* fib_entry;

  fib_entry = fib_lookup(&self->fib, name);
  if(fib_entry && fib_entry->next_hop /* && fib_entry->next_hop->state != DOWN*/) {
    // TODO: We ignored any error here currently.
    forwarder_on_outgoing_interest(self, fib_entry->next_hop, raw_interest, size);
  } else {
    // TODO: Send Nack
    return NDN_FWD_ERROR_INTEREST_REJECTED;
  }
  
  return 0;
}
