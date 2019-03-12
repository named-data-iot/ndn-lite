/*
 * Copyright (C) 2018-2019 Xinyu Ma, Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "forwarder.h"
#include "../util/memory-pool.h"
#include "../util/alarm.h"
#include "../encode/name.h"
#include "../encode/data.h"
#include <stdio.h>

#define NAME_POOL_LEN 4
static uint8_t name_pool[NDN_MEMORY_POOL_RESERVE_SIZE(sizeof(ndn_name_t), NAME_POOL_LEN)];

#define FIB_NAME_MAX_SIZE 100
#define PIT_INTEREST_MAX_SIZE 300
static uint8_t fib_name_pool[NDN_MEMORY_POOL_RESERVE_SIZE(FIB_NAME_MAX_SIZE, \
                                                          NDN_FIB_MAX_SIZE)];
static uint8_t pit_interest_pool[NDN_MEMORY_POOL_RESERVE_SIZE(PIT_INTEREST_MAX_SIZE, \
                                                              NDN_PIT_MAX_SIZE)];
static ndn_forwarder_t instance;

/************************************************************/
/*  Helper Functions Inside Forwarder                       */
/************************************************************/
static int
_fib_insert_name_block(uint8_t* name_block_value, uint32_t name_block_size,
                       ndn_face_intf_t* face, uint8_t cost)
{
  // Compare without truly decoding
  ndn_decoder_t incoming_name;
  decoder_init(&incoming_name, name_block_value, name_block_size);

  // already exists
  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    ndn_decoder_t to_compare;
    decoder_init(&to_compare, instance.fib[i].name_buffer.value,
                 instance.fib[i].name_buffer.size);
    if (ndn_name_compare_block(&to_compare, &incoming_name) == 0 &&
        instance.fib[i].next_hop == face) {
      if (face->state != NDN_FACE_STATE_UP)
        ndn_face_up(face);
      return 0;
    }

    // Re-initialize incoming name decoder
    decoder_init(&incoming_name, name_block_value, name_block_size);
  }

  // find an unused fib entry
  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    if (instance.fib[i].name_buffer.size == NDN_FWD_INVALID_NAME_SIZE) {
      instance.fib[i].name_buffer.value = ndn_memory_pool_alloc(fib_name_pool);

      if (instance.fib[i].name_buffer.value == NULL ||
          name_block_size > FIB_NAME_MAX_SIZE)
        return NDN_OVERSIZE;

      memcpy(instance.fib[i].name_buffer.value, name_block_value,
             name_block_size);

      instance.fib[i].name_buffer.size = name_block_size;
      instance.fib[i].next_hop = face;
      instance.fib[i].cost = cost;

      ndn_face_up(face);

      printf("Forwarder: successfully insert FIB\n");

      return 0;
    }
  }
  return NDN_FWD_FIB_FULL;
}

ndn_forwarder_t*
ndn_forwarder_get_instance(void)
{
  return &instance;
}

static int
forwarder_multicast_strategy(ndn_face_intf_t* face, const uint8_t* raw_interest,
                             uint32_t size, const ndn_pit_entry_t* pit_entry);

/************************************************************/
/*  Definition of PIT table APIs                            */
/************************************************************/

static void
pit_table_init(void)
{
  ndn_memory_pool_init(pit_interest_pool, PIT_INTEREST_MAX_SIZE,
                       NDN_PIT_MAX_SIZE);
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    instance.pit[i].interest_buffer.value = NULL;
    instance.pit[i].interest_buffer.size = NDN_FWD_INVALID_NAME_SIZE;
    instance.pit[i].interest_buffer.max_size = PIT_INTEREST_MAX_SIZE;
    ndn_timer_reset(&instance.pit[i].timer);
  }
}

void
pit_entry_delete(ndn_pit_entry_t* entry)
{
  ndn_memory_pool_free(pit_interest_pool, entry->interest_buffer.value);
  entry->interest_buffer.value = NULL;
  entry->interest_buffer.size = NDN_FWD_INVALID_NAME_SIZE;
}

static ndn_pit_entry_t*
pit_table_find(const uint8_t* interest_block_value, uint32_t interest_block_size)
{
  // Patially decode incoming interest
  ndn_decoder_t incoming_interest;
  decoder_init(&incoming_interest, interest_block_value, interest_block_size);

  // Find
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    ndn_decoder_t to_compare;
    decoder_init(&to_compare, instance.pit[i].interest_buffer.value,
                 instance.pit[i].interest_buffer.size);
    if (ndn_interest_compare_block(&incoming_interest, &to_compare) == 0)
      return &instance.pit[i];

    // Re-initialize incoming interest decoder
    decoder_init(&incoming_interest, interest_block_value, interest_block_size);
  }
  return NULL;
}

static ndn_pit_entry_t*
pit_table_find_or_insert(const uint8_t* interest_block_value,
                         uint32_t interest_block_size)
{
  // Find
  ndn_pit_entry_t* entry = pit_table_find(interest_block_value,
                                          interest_block_size);
  if (entry)
    return entry;

  // Insert
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    if (instance.pit[i].interest_buffer.size == NDN_FWD_INVALID_NAME_SIZE) {
      instance.pit[i].interest_buffer.value = ndn_memory_pool_alloc(pit_interest_pool);

      if (instance.pit[i].interest_buffer.value == NULL ||
          interest_block_size > PIT_INTEREST_MAX_SIZE)
        return NULL;

      memcpy(instance.pit[i].interest_buffer.value, interest_block_value,
             interest_block_size);
      instance.pit[i].interest_buffer.size = interest_block_size;
      instance.pit[i].incoming_face_size = 0;
      return &instance.pit[i];
    }
  }
  return NULL;
}


static void
pit_table_check_and_fire(void)
{
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    if (instance.pit[i].timer.fire_time == NDN_TIMER_INVALID_FIRETIME ||
        instance.pit[i].interest_buffer.size == NDN_FWD_INVALID_NAME_SIZE)
      continue;

    if (instance.pit[i].timer.fire_time <= ndn_alarm_millis_get_now())
    {
      ndn_timer_fire(&instance.pit[i].timer);
      pit_entry_delete(&instance.pit[i]);
    }
  }
}

/************************************************************/
/*  Definition of FIB table APIs                            */
/************************************************************/

static void
fib_table_init(void)
{
  ndn_memory_pool_init(fib_name_pool, FIB_NAME_MAX_SIZE,
                       NDN_PIT_MAX_SIZE);
  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    instance.fib[i].name_buffer.size = NDN_FWD_INVALID_NAME_SIZE;
    instance.fib[i].name_buffer.max_size = FIB_NAME_MAX_SIZE;
    instance.fib[i].name_buffer.value = NULL;
  }
}

static ndn_fib_entry_t*
fib_table_find(const uint8_t* name_block_value, uint32_t name_block_size)
{
  // Compare without truly decoding
  ndn_decoder_t incoming_name;
  decoder_init(&incoming_name, name_block_value, name_block_size);

  for (uint8_t i = 0; i < NDN_FIB_MAX_SIZE; i++) {
    ndn_decoder_t to_compare;
    decoder_init(&to_compare, instance.fib[i].name_buffer.value,
                 instance.fib[i].name_buffer.size);
    int compare_result = ndn_name_compare_block(&to_compare, &incoming_name);
    if (compare_result == -2 || compare_result == 0)
      return &instance.fib[i];

    // Re-initialize incoming name decoder
    decoder_init(&incoming_name, name_block_value, name_block_size);
  }
  return NULL;
}

void
fib_entry_delete(ndn_fib_entry_t* entry)
{
  ndn_memory_pool_free(fib_name_pool, entry->name_buffer.value);
  entry->name_buffer.size = NDN_FWD_INVALID_NAME_SIZE;
}
/************************************************************/
/*  Definition of forwarder APIs                            */
/************************************************************/

// Send data packet out
static int
ndn_forwarder_on_outgoing_data(ndn_face_intf_t* face, const uint8_t* raw_data,
                               uint32_t size)
{
  return ndn_face_send(face, raw_data, size);
}

// Send interest packet out
static int
ndn_forwarder_on_outgoing_interest(ndn_face_intf_t* face, const uint8_t* raw_interest,
                                   uint32_t size)
{
  return ndn_face_send(face, raw_interest, size);
}

ndn_forwarder_t*
ndn_forwarder_init(void)
{
  ndn_memory_pool_init(name_pool, sizeof(ndn_name_t), NAME_POOL_LEN);
  pit_table_init();
  fib_table_init();
  return &instance;
}

int
ndn_forwarder_fib_insert(const ndn_name_t* name_prefix,
                         ndn_face_intf_t* face, uint8_t cost)
{
  uint32_t name_block_size = ndn_name_probe_block_size(name_prefix);
  if (name_block_size <= 0 || name_block_size > FIB_NAME_MAX_SIZE)
    return NDN_OVERSIZE;

  // Encode Name Prefix
  ndn_encoder_t before_insert;
  uint8_t name_block_value[name_block_size];
  encoder_init(&before_insert, name_block_value, name_block_size);
  int r = ndn_name_tlv_encode(&before_insert, name_prefix);
  if (r != NDN_SUCCESS) return NDN_TLV_OP_FAILED;

  return _fib_insert_name_block(name_block_value, name_block_size,
                                face, cost);
}

int
ndn_forwarder_pit_load_timeout(const uint8_t* interest_block, uint32_t interest_size,
                               handler timeout_handler)
{
  ndn_pit_entry_t* entry = pit_table_find(interest_block, interest_size);
  if (!entry)
    return NDN_FWD_PIT_NO_MATCH;

  // Skip name to get lifetime
  ndn_decoder_t decoder;
  uint32_t probe;
  uint64_t lifetime = 0;
  decoder_init(&decoder, interest_block, interest_size);

  // Interest Header
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);

  // Name Header
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_move_forward(&decoder, probe);

  // Servarl Optional Elements
  while (decoder.offset < interest_size && !lifetime)
  {
    decoder_get_type(&decoder, &probe);
    switch (probe) {
      case TLV_CanBePrefix:
        decoder_get_length(&decoder, &probe);
        break;
      case TLV_MustBeFresh:
        decoder_get_length(&decoder, &probe);
        break;
      case TLV_Nonce:
        decoder_get_length(&decoder, &probe);
        decoder_move_forward(&decoder, probe);
        break;
      case TLV_InterestLifetime:
        decoder_get_length(&decoder, &probe);
        decoder_get_uint_value(&decoder, probe, &lifetime);
        break;
    }
  }

  uint64_t fire_time = ndn_alarm_millis_get_now() + lifetime;
  ndn_timer_init(&entry->timer, timeout_handler, fire_time,
                 entry->interest_buffer.value, entry->interest_buffer.size);
  return NDN_SUCCESS;
}

int
ndn_forwarder_on_incoming_data(ndn_forwarder_t* self, ndn_face_intf_t* face,
                               const uint8_t* raw_data, uint32_t size)
{
  (void)face;
  printf("Forwarder: on Data\n");

  // Compare Incoming Data aganist PIT without truly decoding
  ndn_decoder_t incoming_data;
  decoder_init(&incoming_data, raw_data, size);

  // Match with pit
  for (uint8_t i = 0; i < NDN_PIT_MAX_SIZE; i++) {
    ndn_decoder_t to_compare;
    decoder_init(&to_compare, self->pit[i].interest_buffer.value,
                 self->pit[i].interest_buffer.size);
    int compare_result = ndn_data_interest_compare_block(&incoming_data, &to_compare);
    if (compare_result == 0)
    {
      // Send out data
      for (uint8_t j = 0; j < self->pit[i].incoming_face_size; j++) {
        ndn_forwarder_on_outgoing_data(self->pit[i].incoming_face[j], raw_data, size);
      }
      // Delete PIT Entry
      pit_entry_delete(&self->pit[i]);
      break;
    }

    // Re-initialize incoming data decoder
    decoder_init(&incoming_data, raw_data, size);
  }

  return 0;
}

int
ndn_forwarder_on_incoming_interest(ndn_forwarder_t* self, ndn_face_intf_t* face,
                                   const uint8_t* raw_interest, uint32_t size)
{
  printf("Forwarder: on Interest\n");

  (void)self;
  int ret = 0;

  // Insert into PIT
  ndn_pit_entry_t* pit_entry = pit_table_find_or_insert(raw_interest, size);
  if (pit_entry == NULL) {
    return NDN_FWD_PIT_FULL;
  }
  pit_entry_add_incoming_face(pit_entry, face);

  // Multicast Strategy
  ret = forwarder_multicast_strategy(face, raw_interest, size, pit_entry);

  // Reject PIT
  if (ret != 0) {
    pit_entry_delete(pit_entry);
  }

  return ret;
}

int
ndn_forwarder_process(ndn_forwarder_t* self)
{
  (void)self;
  pit_table_check_and_fire();

  // no errors happen during process
  return NDN_SUCCESS;
}

static int
forwarder_multicast_strategy(ndn_face_intf_t* face, const uint8_t* raw_interest,
                             uint32_t size, const ndn_pit_entry_t* pit_entry)
{
  (void)pit_entry;
  ndn_fib_entry_t* fib_entry;

  // Partially decode Interest to get Name TLV
  ndn_decoder_t incoming_interest;
  decoder_init(&incoming_interest, raw_interest, size);

  uint32_t probe, name_buffer_size = 0;
  int ret_val = -1;

  decoder_get_type(&incoming_interest, &probe);
  if (probe != TLV_Interest) return NDN_WRONG_TLV_TYPE;
  ret_val = decoder_get_length(&incoming_interest, &probe);
  if (ret_val != NDN_SUCCESS) return NDN_WRONG_TLV_LENGTH;

  const uint8_t* name_buffer_value = incoming_interest.input_value +
                                     incoming_interest.offset;
  decoder_get_type(&incoming_interest, &probe);
  if (probe != TLV_Name) return NDN_WRONG_TLV_TYPE;
  ret_val = decoder_get_length(&incoming_interest, &name_buffer_size);
  if (ret_val != NDN_SUCCESS) return NDN_WRONG_TLV_LENGTH;

  fib_entry = fib_table_find(name_buffer_value, name_buffer_size);
  if (fib_entry && fib_entry->next_hop && fib_entry->next_hop != face) {
    ndn_forwarder_on_outgoing_interest(fib_entry->next_hop, raw_interest, size);
  }
  else {
    // TODO: Send Nack
    return NDN_FWD_INTEREST_REJECTED;
  }
  return 0;
}
