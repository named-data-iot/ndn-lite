/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */
#define ENABLE_NDN_LOG_INFO 0
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1
#include "forwarder.h"
#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include "../encode/tlv.h"
#include "../encode/name.h"
#include "../encode/data.h"
#include "../util/logger.h"

uint8_t encoding_buf[2048];

static ndn_forwarder_t forwarder;

// face_id is optional
static int
fwd_on_incoming_interest(uint8_t* interest,
                         size_t length,
                         interest_options_t* options,
                         uint8_t* name,
                         size_t name_len,
                         ndn_table_id_t face_id);

static int
fwd_on_outgoing_interest(uint8_t* interest,
                         size_t length,
                         uint8_t* name,
                         size_t name_len,
                         ndn_pit_entry_t* entry,
                         ndn_table_id_t face_id);

static int
fwd_data_pipeline(uint8_t* data,
                  size_t length,
                  uint8_t* name,
                  size_t name_len,
                  ndn_table_id_t face_id);

static ndn_bitset_t
fwd_multicast(uint8_t* packet,
              size_t length,
              ndn_bitset_t out_faces,
              ndn_table_id_t in_face);

/////////////////////////////////////////////////////////////////////////////////

void
ndn_forwarder_init(void)
{
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

  ndn_cs_init(ptr, NDN_CS_MAX_SIZE, forwarder.nametree);
  forwarder.cs = (ndn_cs_t*)ptr;
  ptr += NDN_CS_RESERVE_SIZE(NDN_CS_MAX_SIZE);

  dll_init();
}

const ndn_forwarder_t*
ndn_forwarder_get(void){
  return &forwarder;
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
ndn_forwarder_add_route_by_str(ndn_face_intf_t* face, const char* prefix, size_t length)
{
  ndn_name_t name_prefix;
  ndn_name_from_string(&name_prefix, prefix, length);
  ndn_encoder_t encoder;
  encoder_init(&encoder, encoding_buf, sizeof(encoding_buf));
  ndn_name_tlv_encode(&encoder, &name_prefix);
  return ndn_forwarder_add_route(face, encoder.output_value, encoder.offset);
}

int
ndn_forwarder_add_route_by_name(ndn_face_intf_t* face, const ndn_name_t* prefix)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, encoding_buf, sizeof(encoding_buf));
  ndn_name_tlv_encode(&encoder, prefix);
  return ndn_forwarder_add_route(face, encoder.output_value, encoder.offset);
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
ndn_forwarder_register_prefix(uint8_t* prefix, size_t length,
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
}

int
ndn_forwarder_register_name_prefix(const ndn_name_t* prefix,
                                   ndn_on_interest_func on_interest,
                                   void* userdata)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, encoding_buf, sizeof(encoding_buf));
  ndn_name_tlv_encode(&encoder, prefix);
  return ndn_forwarder_register_prefix(encoder.output_value, encoder.offset, on_interest, userdata);
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
ndn_forwarder_express_interest(uint8_t* interest, size_t length,
                               ndn_on_data_func on_data,
                               ndn_on_timeout_func on_timeout,
                               void* userdata)
{
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

  ndn_cs_entry_t* cs_entry;
  cs_entry = ndn_cs_prefix_match(forwarder.cs, name, name_len);
  if (cs_entry != NULL){
    NDN_LOG_DEBUG("[FORWARDER] (ndn_forwarder_express_interest) Prefix match in content store found\n");
    if (cs_entry->options.can_be_prefix || ndn_cs_find(forwarder.cs, name, name_len) == cs_entry){

      // check if either the CS entry is fresh or must_be_fresh of the entry is false
      int cs_entry_freshness = dll_check_one_cs_entry_freshness(cs_entry);
      if ((cs_entry_freshness == 0) || ((cs_entry_freshness == -1) && (cs_entry->options.must_be_fresh == false))){
        cs_entry->options = options;
        cs_entry->on_data = on_data;
        cs_entry->userdata = userdata;

        cs_entry->last_time = ndn_time_now_ms();

        if (cs_entry->on_data != NULL){
          cs_entry->on_data(cs_entry->content, cs_entry->content_len, cs_entry->userdata);
        }

        return NDN_SUCCESS;
      }else{
        NDN_LOG_DEBUG("The found CS entry is not fresh anymore, but must be fresh\n");

        dll_remove_cs_entry(cs_entry);
      }
    }
  }

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
ndn_forwarder_express_interest_struct(ndn_interest_t* interest,
                                      ndn_on_data_func on_data,
                                      ndn_on_timeout_func on_timeout,
                                      void* userdata)
{
  ndn_encoder_t encoder;
  encoder_init(&encoder, encoding_buf, sizeof(encoding_buf));
  ndn_interest_tlv_encode(&encoder, interest);
  return ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                 on_data, on_timeout, userdata);
}

int
ndn_forwarder_put_data(uint8_t* data, size_t length)
{
  int ret;
  uint8_t *name;
  size_t name_len;

  if(data == NULL)
    return NDN_INVALID_POINTER;
  ret = tlv_data_get_name(data, length, &name, &name_len);
  if(ret != NDN_SUCCESS)
    return ret;

  return fwd_data_pipeline(data, length, name, name_len, NDN_INVALID_ID);
}

int
ndn_forwarder_receive(ndn_face_intf_t* face, uint8_t* packet, size_t length)
{
  uint32_t type, val_len;
  uint8_t* buf;
  uint8_t *name;
  size_t name_len;
  interest_options_t options;
  int ret;
  ndn_table_id_t face_id = (face ? face->face_id : NDN_INVALID_ID);

  if (packet == NULL)
    return NDN_INVALID_POINTER;

  buf = tlv_get_type_length(packet, length, &type, &val_len);
  if (val_len != length - (buf - packet))
    return NDN_WRONG_TLV_LENGTH;

  if (type == TLV_Interest) {
    ret = tlv_interest_get_header(packet, length, &options, &name, &name_len);
    if (ret != NDN_SUCCESS)
      return ret;
    return fwd_on_incoming_interest(packet, length, &options, name, name_len, face_id);
  }
  else if(type == TLV_Data) {
    ret = tlv_data_get_name(packet, length, &name, &name_len);
    if (ret != NDN_SUCCESS)
      return ret;
    return fwd_data_pipeline(packet, length, name, name_len, face_id);
  }
  else {
    return NDN_WRONG_TLV_TYPE;
  }
}

static int
fwd_on_incoming_interest(uint8_t* interest,
                         size_t length,
                         interest_options_t* options,
                         uint8_t* name,
                         size_t name_len,
                         ndn_table_id_t face_id)
{
  ndn_cs_entry_t* cs_entry;

  cs_entry = ndn_cs_prefix_match(forwarder.cs, name, name_len);
  if (cs_entry == NULL){
    NDN_LOG_DEBUG("[FORWARDER] (fwd_on_incoming_interest) No prefix match in content store found\n");
  }else{
    NDN_LOG_DEBUG("[FORWARDER] (fwd_on_incoming_interest) Prefix match in content store found\n");
    if (cs_entry->options.can_be_prefix || ndn_cs_find(forwarder.cs, name, name_len) == cs_entry){

      // check if either the CS entry is either fresh or must_be_fresh of the entry is false
      int cs_entry_freshness = dll_check_one_cs_entry_freshness(cs_entry);
      if ((cs_entry_freshness == 0) || ((cs_entry_freshness == -1) && (cs_entry->options.must_be_fresh == false))){
        // Randomized dead nonce list
        if(cs_entry->options.nonce == options->nonce && options->nonce != 0){
          NDN_LOG_ERROR("[FORWARDER] Drop by dead nonce\n");
          return NDN_FWD_INTEREST_REJECTED;
        }
        if(cs_entry->on_data == NULL){
          // Update the options (lifetime) only when it's not expressed by an application, as done with the pit_entry below.
          cs_entry->options = *options;
        }
        cs_entry->last_time = ndn_time_now_ms();

        ndn_bitset_t incoming_faces;
        incoming_faces = bitset_set(0, face_id);

        fwd_multicast(cs_entry->content, cs_entry->content_len, incoming_faces, NDN_INVALID_ID);

        return NDN_SUCCESS;
      }else{
        NDN_LOG_DEBUG("The found CS entry is not fresh anymore, but must be fresh\n");

        dll_remove_cs_entry(cs_entry);
      }
    }
  }

  ndn_pit_entry_t *pit_entry;

  pit_entry = ndn_pit_find_or_insert(forwarder.pit, name, name_len);
  if (pit_entry == NULL){
    return NDN_FWD_PIT_FULL;
  }

  // Randomized dead nonce list
  if(pit_entry->options.nonce == options->nonce && options->nonce != 0){
    NDN_LOG_ERROR("[FORWARDER] Drop by dead nonce\n");
    return NDN_FWD_INTEREST_REJECTED;
  }
  if(pit_entry->on_data == NULL && pit_entry->on_timeout == NULL){
    // Update the options (lifetime) only when it's not expressed by an application.
    // I'm sorry I don't have a clear idea on this. Maybe we should separate user's lifetime
    // and forwarded Interest's lifetime.
    pit_entry->options = *options;
  }
  pit_entry->last_time = ndn_time_now_ms();
  if(face_id != NDN_INVALID_ID){
    pit_entry->incoming_faces = bitset_set(pit_entry->incoming_faces, face_id);
  }

  return fwd_on_outgoing_interest(interest, length, name, name_len, pit_entry, face_id);
}

static int
fwd_data_pipeline(uint8_t* data,
                  size_t length,
                  uint8_t* name,
                  size_t name_len,
                  ndn_table_id_t face_id)
{
  ndn_cs_entry_t* cs_entry;

  cs_entry = ndn_cs_prefix_match(forwarder.cs, name, name_len);
  if (cs_entry != NULL){
    NDN_LOG_DEBUG("[FORWARDER] (fwd_data_pipeline) cs entry already found\n");

    // update existing CS entry
    ndn_insert_cs_entry_with_content(cs_entry, data, length);

    if (cs_entry->options.can_be_prefix || ndn_cs_find(forwarder.cs, name, name_len) == cs_entry){
      if (cs_entry->on_data != NULL){
          cs_entry->on_data(cs_entry->content, cs_entry->content_len, cs_entry->userdata);
          return NDN_SUCCESS;
        }
    }
  }else{
    NDN_LOG_DEBUG("[FORWARDER] (fwd_data_pipeline) No cs entry found, inserting new one\n");

    // try to insert new CS entry
    cs_entry = ndn_cs_find_or_insert(forwarder.cs, name, name_len);
    if (cs_entry == NULL){
      NDN_LOG_DEBUG("[FORWARDER] (fwd_data_pipeline) The CS table is already full\n");
      // CS table is full, remove all entries that are not fresh or first/oldest entry from CS
      int deleted = dll_check_all_cs_entry_freshness();
      if (deleted == 0)
        dll_remove_first();

      // insert new entry after creating space
      cs_entry = ndn_cs_find_or_insert(forwarder.cs, name, name_len);
    }

    if (cs_entry == NULL)
      NDN_LOG_DEBUG("[FORWARDER] (fwd_data_pipeline) Could not create new cs_entry\n");

    // insert the CS entry with the content into the dll
    ndn_insert_cs_entry_with_content(cs_entry, data, length);
    dll_insert(cs_entry);
  }

  ndn_pit_entry_t* pit_entry;

  pit_entry = ndn_pit_prefix_match(forwarder.pit, name, name_len);
  if (pit_entry == NULL) {
    return NDN_FWD_NO_ROUTE;
  }
  if (!pit_entry->options.can_be_prefix) {
    // Quick and dirty solution
    if (ndn_pit_find(forwarder.pit, name, name_len) != pit_entry)
      return NDN_FWD_NO_ROUTE;
  }

  if (pit_entry->on_data != NULL) {
    pit_entry->on_data(data, length, pit_entry->userdata);
  }

  fwd_multicast(data, length, pit_entry->incoming_faces, face_id);

  ndn_pit_remove_entry(forwarder.pit, pit_entry);

  return NDN_SUCCESS;
}

static ndn_bitset_t
fwd_multicast(uint8_t* packet,
              size_t length,
              ndn_bitset_t out_faces,
              ndn_table_id_t in_face)
{
  ndn_table_id_t id;
  ndn_face_intf_t* face;
  ndn_bitset_t ret = 0;

  while(out_faces != 0){
    id = bitset_pop_least(&out_faces);
    face = forwarder.facetab->slots[id];
    if(id != in_face && face != NULL){
      ndn_face_send(face, packet, length);
      ret = bitset_set(ret, id);
    }
  }
  return ret;
}

static int
fwd_on_outgoing_interest(uint8_t* interest,
                         size_t length,
                         uint8_t* name,
                         size_t name_len,
                         ndn_pit_entry_t* entry,
                         ndn_table_id_t face_id)
{
  ndn_fib_entry_t* fib_entry;
  int strategy;
  uint8_t *hop_limit;
  ndn_bitset_t outfaces;

  fib_entry = ndn_fib_prefix_match(forwarder.fib, name, name_len);
  if(fib_entry == NULL){
    NDN_LOG_ERROR("[FORWARDER] Drop by no route\n");
    return NDN_FWD_NO_ROUTE;
  }

  if(fib_entry->on_interest){
    strategy = fib_entry->on_interest(interest, length, fib_entry->userdata);
  }else{
    strategy = NDN_FWD_STRATEGY_MULTICAST;
  }

  // The interest may be satisfied immediately so check again
  if(entry->nametree_id == NDN_INVALID_ID){
    return NDN_SUCCESS;
  }

  hop_limit = tlv_interest_get_hoplimit_ptr(interest, length);
  if(hop_limit != NULL){
    if(*hop_limit <= 0){
      return NDN_FWD_INTEREST_REJECTED;
    }
    // If the Interest is received from another hop
    if(face_id != NDN_INVALID_ID){
      *hop_limit -= 1;
    }
  }

  outfaces = (fib_entry->nexthop & (~entry->outgoing_faces));
  if(strategy == NDN_FWD_STRATEGY_MULTICAST){
    entry->outgoing_faces |= fwd_multicast(interest, length, outfaces, face_id);
  }

  return NDN_SUCCESS;
}
