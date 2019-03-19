/*
 * Copyright (C) 2018-2019 Xinyu Ma, Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "forwarder.h"
<<<<<<< HEAD
#include "pit.h"
#include "fib.h"
#include "face-table.h"
#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include "../encode/tlv.h"

#define NDN_FORWARDER_RESERVE_SIZE(nametree_size, facetab_size, fib_size, pit_size) \
  (NDN_NAMETREE_RESERVE_SIZE(nametree_size) + \
   NDN_FACE_TABLE_RESERVE_SIZE(facetab_size) + \
   NDN_FIB_RESERVE_SIZE(fib_size) + \
   NDN_PIT_RESERVE_SIZE(pit_size))

#define NDN_FORWARDER_DEFAULT_SIZE \
  NDN_FORWARDER_RESERVE_SIZE(NDN_NAMETREE_MAX_SIZE, \
                             NDN_FACE_TABLE_MAX_SIZE, \
                             NDN_FIB_MAX_SIZE, \
                             NDN_PIT_MAX_SIZE)

/**
 * NDN-Lite forwarder.
 * We will support content support in future versions.
 * The NDN forwarder is a singleton in an application.
 */
typedef struct ndn_forwarder {
  ndn_nametree_t* nametree;
  ndn_face_table_t* facetab;
=======
#include "../util/memory-pool.h"
#include "../util/alarm.h"
#include "../encode/light/data-light.h"
#include "../encode/light/interest-light.h"
#include <stdio.h>
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee

  /**
   * The forwarding information base (FIB).
   */
  ndn_fib_t* fib;
  /**
   * The pending Interest table (PIT).
   */
  ndn_pit_t* pit;

<<<<<<< HEAD
  uint8_t memory[NDN_FORWARDER_DEFAULT_SIZE];
} ndn_forwarder_t;

static ndn_forwarder_t forwarder;
=======
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
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee

// face_id is optional
static int
<<<<<<< HEAD
fwd_on_incoming_interest(uint8_t* interest,
                         size_t length,
                         interest_options_t* options,
                         uint8_t* name,
                         size_t name_len,
                         uint16_t face_id);
=======
forwarder_multicast_strategy(ndn_face_intf_t* face, const uint8_t* raw_interest,
                             uint32_t size, const ndn_pit_entry_t* pit_entry);
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee

static int
fwd_on_outgoing_interest(uint8_t* interest,
                         size_t length,
                         uint8_t* name,
                         size_t name_len,
                         ndn_pit_entry_t* entry,
                         uint16_t face_id);

static int
fwd_data_pipeline(uint8_t* data,
                  size_t length,
                  uint8_t* name,
                  size_t name_len,
                  uint16_t face_id);

static void
fwd_multicast(uint8_t* packet,
              size_t length,
              ndn_bitset_t out_faces,
              uint16_t in_face);

/////////////////////////// /////////////////////////// ///////////////////////////

void
ndn_forwarder_init(void)
{
<<<<<<< HEAD
  uint8_t* ptr = (uint8_t*)forwarder.memory;
  ndn_msgqueue_init();

  ndn_nametree_init(ptr, NDN_NAMETREE_MAX_SIZE);
  forwarder.nametree = (ndn_nametree_t*)ptr;
  ptr += NDN_NAMETREE_RESERVE_SIZE(NDN_NAMETREE_MAX_SIZE);

  ndn_facetab_init(ptr, NDN_FACE_TABLE_MAX_SIZE);
  forwarder.facetab = (ndn_face_table_t*)ptr;
  ptr += NDN_FACE_TABLE_RESERVE_SIZE(NDN_FACE_TABLE_MAX_SIZE);

  ndn_fib_init(ptr, NDN_FIB_MAX_SIZE, forwarder.nametree);
  forwarder.fib = (ndn_fib_t*)ptr;
  ptr += NDN_FIB_RESERVE_SIZE(NDN_FIB_MAX_SIZE);

  ndn_pit_init(ptr, NDN_PIT_MAX_SIZE, forwarder.nametree);
  forwarder.pit = (ndn_pit_t*)ptr;
  ptr += NDN_PIT_RESERVE_SIZE(NDN_PIT_MAX_SIZE);
}

void
ndn_forwarder_process(void){
  ndn_msgqueue_process();
}

int
ndn_forwarder_register_face(ndn_face_intf_t* face)
{
  if(face == NULL)
    return NDN_INVALID_POINTER;
  if(face->face_id != NDN_INVALID_ID)
    return NDN_FWD_NO_EFFECT;
  face->face_id = ndn_facetab_register(forwarder.facetab, face);
  if(face->face_id == NDN_INVALID_ID)
    return NDN_FWD_FACE_TABLE_FULL;
  return NDN_SUCCESS;
}

int
ndn_forwarder_unregister_face(ndn_face_intf_t* face)
{
  if(face == NULL)
    return NDN_INVALID_POINTER;
  if(face->face_id == NDN_INVALID_ID)
    return NDN_FWD_NO_EFFECT;
  if(face->face_id >= forwarder.facetab->capacity)
    return NDN_FWD_INVALID_FACE;
  ndn_fib_unregister_face(forwarder.fib, face->face_id);
  ndn_pit_unregister_face(forwarder.pit, face->face_id);
  ndn_facetab_unregister(forwarder.facetab, face->face_id);
  face->face_id = NDN_INVALID_ID;
  return NDN_SUCCESS;
}

int
ndn_forwarder_add_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length){
  int ret;
  ndn_fib_entry_t* fib_entry;

  if(face == NULL)
    return NDN_INVALID_POINTER;
  if(face->face_id >= forwarder.facetab->capacity)
    return NDN_FWD_INVALID_FACE;
  ret = tlv_check_type_length(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  fib_entry = ndn_fib_find_or_insert(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_FIB_FULL;
  fib_entry->nexthop = bitset_set(fib_entry->nexthop, face->face_id);
  return NDN_SUCCESS;
}

int
ndn_forwarder_remove_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length)
{
  int ret;

  if(face == NULL)
    return NDN_INVALID_POINTER;
  if(face->face_id >= forwarder.facetab->capacity)
    return NDN_FWD_INVALID_FACE;
  ret = tlv_check_type_length(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  ndn_fib_entry_t* fib_entry = ndn_fib_find(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_NO_EFFECT;
  fib_entry->nexthop = bitset_unset(fib_entry->nexthop, face->face_id);
  ndn_fib_remove_entry_if_empty(forwarder.fib, fib_entry);
  return NDN_SUCCESS;
}

int
ndn_forwarder_remove_all_routes(uint8_t* prefix, size_t length)
{
  int ret = tlv_check_type_length(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  ndn_fib_entry_t* fib_entry = ndn_fib_find(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_NO_EFFECT;
  fib_entry->nexthop = 0;
  ndn_fib_remove_entry_if_empty(forwarder.fib, fib_entry);
  return NDN_SUCCESS;
}

int
ndn_forwarder_register_prefix(uint8_t* prefix,
                              size_t length,
                              ndn_on_interest_func on_interest,
                              void* userdata)
{
  int ret = tlv_check_type_length(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;
  if (on_interest == NULL)
    return NDN_INVALID_POINTER;

  ndn_fib_entry_t* fib_entry = ndn_fib_find_or_insert(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_FIB_FULL;
  fib_entry->on_interest = on_interest;
  fib_entry->userdata = userdata;
  return NDN_SUCCESS;
=======
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
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
}

int
ndn_forwarder_unregister_prefix(uint8_t* prefix, size_t length)
{
  int ret = tlv_check_type_length(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  ndn_fib_entry_t* fib_entry = ndn_fib_find(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_NO_EFFECT;
  fib_entry->on_interest = NULL;
  fib_entry->userdata = NULL;
  ndn_fib_remove_entry_if_empty(forwarder.fib, fib_entry);
  return NDN_SUCCESS;
}

int
ndn_forwarder_express_interest(uint8_t* interest,
                               size_t length,
                               ndn_on_data_func on_data,
                               ndn_on_timeout_func on_timeout,
                               void* userdata)
{
<<<<<<< HEAD
  int ret;
  interest_options_t options;
  uint8_t *name;
  size_t name_len;
  ndn_pit_entry_t* pit_entry;

  if(interest == NULL || on_data == NULL)
    return NDN_INVALID_POINTER;

  ret = tlv_interest_get_header(interest, length, &options, &name, &name_len);
  if(ret != NDN_SUCCESS)
    return ret;

  pit_entry = ndn_pit_find_or_insert(forwarder.pit, name, name_len);
  if (pit_entry == NULL)
    return NDN_FWD_PIT_FULL;
  pit_entry->options = options;
  pit_entry->on_data = on_data;
  pit_entry->on_timeout = on_timeout;
  pit_entry->userdata = userdata;

  pit_entry->last_time = pit_entry->express_time = ndn_time_now_ms();

  return fwd_on_outgoing_interest(interest, length, name, name_len, pit_entry, NDN_INVALID_ID);
}

int
ndn_forwarder_put_data(uint8_t* data, size_t length)
{
  int ret;
  uint8_t *name;
  size_t name_len;

  if(data == NULL)
    return NDN_INVALID_POINTER;
  ret = tlv_data_get_header(data, length, &name, &name_len);
  if(ret != NDN_SUCCESS)
    return ret;

  return fwd_data_pipeline(data, length, name, name_len, NDN_INVALID_ID);
}

int
ndn_forwarder_receive(ndn_face_intf_t* face, uint8_t* packet, size_t length){
  uint32_t type, val_len;
  uint8_t* buf;
  uint8_t *name;
  size_t name_len;
  interest_options_t options;
  int ret;
  uint16_t face_id = (face ? face->face_id : NDN_INVALID_ID);

  if(packet == NULL)
    return NDN_INVALID_POINTER;

  buf = tlv_get_type_length(packet, length, &type, &val_len);
  if(val_len != length - (buf - packet))
    return NDN_WRONG_TLV_LENGTH;

  if(type == TLV_Interest){
    ret = tlv_interest_get_header(packet, length, &options, &name, &name_len);
    if(ret != NDN_SUCCESS)
      return ret;
    return fwd_on_incoming_interest(packet, length, &options, name, name_len, face_id);
  }else if(type == TLV_Data){
    ret = tlv_data_get_header(packet, length, &name, &name_len);
    if(ret != NDN_SUCCESS)
      return ret;
    return fwd_data_pipeline(packet, length, name, name_len, face_id);
  }else{
    return NDN_WRONG_TLV_TYPE;
  }
}

static int
fwd_on_incoming_interest(uint8_t* interest,
                         size_t length,
                         interest_options_t* options,
                         uint8_t* name,
                         size_t name_len,
                         uint16_t face_id)
{
  ndn_pit_entry_t *pit_entry;

  pit_entry = ndn_pit_find_or_insert(forwarder.pit, name, name_len);
  if (pit_entry == NULL)
    return NDN_FWD_PIT_FULL;
  
  if(pit_entry->options.nonce == options->nonce && options->nonce != 0){
    return NDN_FWD_INTEREST_REJECTED;
  }
  if(pit_entry->on_data == NULL && pit_entry->on_timeout == NULL){
    pit_entry->options = *options;
  }
  pit_entry->last_time = ndn_time_now_ms();
  if(face_id != NDN_INVALID_ID){
    pit_entry->incoming_faces = bitset_set(pit_entry->incoming_faces, face_id);
=======
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
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
  }

  return fwd_on_outgoing_interest(interest, length, name, name_len, pit_entry, face_id);
}

<<<<<<< HEAD
static int
fwd_data_pipeline(uint8_t* data,
                  size_t length,
                  uint8_t* name,
                  size_t name_len,
                  uint16_t face_id)
{
  ndn_pit_entry_t* pit_entry;

  pit_entry = ndn_pit_prefix_match(forwarder.pit, name, name_len);
  if(pit_entry == NULL){
    return NDN_FWD_NO_ROUTE;
  }
  if(!pit_entry->options.can_be_prefix){
    // Quick and dirty solution
    if(ndn_pit_find(forwarder.pit, name, name_len) != pit_entry)
      return NDN_FWD_NO_ROUTE;
  }

  if(pit_entry->on_data != NULL){
    pit_entry->on_data(data, length, pit_entry->userdata);
=======
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
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
  }

<<<<<<< HEAD
  fwd_multicast(data, length, pit_entry->incoming_faces, face_id);
=======
  // Multicast Strategy
  ret = forwarder_multicast_strategy(face, raw_interest, size, pit_entry);
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee

  ndn_pit_remove_entry(forwarder.pit, pit_entry);

<<<<<<< HEAD
  return NDN_SUCCESS;
}

static void
fwd_multicast(uint8_t* packet,
              size_t length,
              ndn_bitset_t out_faces,
              uint16_t in_face)
{
  uint16_t id;
  ndn_face_intf_t* face;

  for(id = 0; id < forwarder.facetab->capacity; id ++){
    face = forwarder.facetab->slots[id];
    if(id == in_face || face == NULL)
      continue;
    ndn_face_send(face, packet, length);
  }
=======
  return ret;
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
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
<<<<<<< HEAD
fwd_on_outgoing_interest(uint8_t* interest,
                         size_t length,
                         uint8_t* name,
                         size_t name_len,
                         ndn_pit_entry_t* entry,
                         uint16_t face_id)
=======
forwarder_multicast_strategy(ndn_face_intf_t* face, const uint8_t* raw_interest,
                             uint32_t size, const ndn_pit_entry_t* pit_entry)
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
{
  ndn_fib_entry_t* fib_entry;
<<<<<<< HEAD
  int action = 0;
  uint8_t *hop_limit;

  fib_entry = ndn_fib_prefix_match(forwarder.fib, name, name_len);
  if(fib_entry == NULL){
    return NDN_FWD_NO_ROUTE;
=======

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
>>>>>>> ea49b8a70f1e420ca01a12f4e2d4fdb3d28cecee
  }

  if(fib_entry->on_interest){
    action = fib_entry->on_interest(interest, length, fib_entry->userdata);
  }

  // The interest may be satisfied immediately so check again
  if(entry->nametree_id == NDN_INVALID_ID){
    return NDN_SUCCESS;
  }

  (void)action;
  hop_limit = tlv_interest_get_hoplimit_ptr(interest, length);
  if(hop_limit != NULL){
    if(*hop_limit <= 0){
      return NDN_FWD_INTEREST_REJECTED;
    }
    // If the Interest is received from another hop
    if(face_id != NDN_INVALID_ID){
      if(*hop_limit <= 0){
        return NDN_FWD_INTEREST_REJECTED;
      }
      *hop_limit -= 1;
    }
  }
  fwd_multicast(interest, length, fib_entry->nexthop, face_id);

  return NDN_SUCCESS;
}
