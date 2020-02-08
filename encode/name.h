/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_NAME_H
#define NDN_ENCODING_NAME_H

#include "name-component.h"
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to represent the Name.
 * This structure is memory expensive so please be careful when using it.
 */
typedef struct ndn_name {
  /**
   * The array of name components contained in this name (not including T and L)
   */
  name_component_t components[NDN_NAME_COMPONENTS_SIZE];
  /**
   * The number of name components
   */
  uint8_t components_size;
} ndn_name_t;

/**
 * Print a name.
 * @param name. Input. The name to be printed.
 */
void
ndn_name_print(const ndn_name_t* name);

/**
 * Init an empty Name structure.
 */
void
ndn_name_init(ndn_name_t *name);

/**
 * Decode the Name from wire format (TLV block).
 * @param decoder. Input. The decoder who keeps the decoding result and the state.
 * @param name. Output. The Name decoded from TLV block.
 * @return 0 if there is no error.
 */
int
ndn_name_tlv_decode(ndn_decoder_t* decoder, ndn_name_t* name);

/**
 * Decode an Name TLV block into an Name. This function will do memory copy.
 * @param name. Output. The Name to which the TLV block will be decoded.
 * @param block. Input. The Name TLV.
 * @return 0 if decoding is successful.
 */
int
ndn_name_from_block(ndn_name_t* name, const uint8_t* block_value, uint32_t block_size);

/**
 * Init a name block from a string. This funcition will do memory copy and
 * only support regular string; not support URI currently.
 * @param name. Output. The Name to be inited.
 * @param string. Input. The string from which Name is inited.
 * @param size. Input. Size of the input string.
 * @return 0 if there is no error.
 */
int
ndn_name_from_string(ndn_name_t* name, const char* string, uint32_t size);

/**
 * Appends a component to the end of a name. This function will do memory copy.
 * @param name. Output. The name to append to.
 * @param component. Input. The name component to append with.
 * @return 0 if there is no error.
 */
int
ndn_name_append_component(ndn_name_t* name, const name_component_t* component);

/**
 * Appends bytes as a component to the end of a name. This function will do memory copy.
 * @param name. Output. The name to append to.
 * @param value. Input. Value.
 * @param size. Input. Size of bytes.
 * @return 0 if there is no error.
 */
int
ndn_name_append_bytes_component(ndn_name_t* name, const uint8_t* value, uint32_t size);

/**
 * Appends a string component to the end of a name. This function will do memory copy.
 * @param name. Output. The name to append to.
 * @param string. Input. The string from which the name component is generated.
 * @param size. Input. Size of the input string.
 * @return 0 if there is no error.
 */
int
ndn_name_append_string_component(ndn_name_t* name, const char* string, uint32_t size);

/**
 * Appends another name to the end of a name. This function will do memory copy.
 * @param lhs. Output. The name to append to.
 * @param rhs. Input. The name to append with.
 * @return 0 if there is no error.
 */
int
ndn_name_append_name(ndn_name_t* lhs, const ndn_name_t* rhs);

int
ndn_name_append_keyid(ndn_name_t* name, uint32_t key_id);

/**
 * Probe the size of a Name TLV block before encoding it from a Name structure.
 * This function is used to check whether the output buffer size is enough or not.
 * @param name. Input. The Name structure to be probed.
 * @return the length of the expected Name TLV block.
 */
static inline uint32_t
ndn_name_probe_block_size(const ndn_name_t *name)
{
  uint32_t value_size = 0;
  for (uint32_t i = 0; i < name->components_size; i++) {
    value_size += name_component_probe_block_size(&name->components[i]);
  }
  return encoder_probe_block_size(TLV_Name, value_size);
}

/**
 * Encode the Name structure into wire format (TLV block). This function will do memory copy.
 * Need to call ndn_name_probe_block_size() to initialize output block in advance.
 * @param encoder. Output. The encoder who keeps the encoding result and the state.
 * @param name. Input. The Name structure to be encoded.
 * @return 0 if there is no error.
 */
int
ndn_name_tlv_encode(ndn_encoder_t* encoder, const ndn_name_t *name);

/**
 * Compare two Name.
 * @param lhs. Input. Left-hand-side Name.
 * @param rhs. Input. Right-hand-side Name.
 * @return 0 if @p lhs == @p rhs.
 */
int
ndn_name_compare(const ndn_name_t* lhs, const ndn_name_t* rhs);

/**
 * Compare sub-names of two names.
 * @param lhs. Input. Left-hand-side Name.
 * @param lhs_b. Input. Beginning index of left-hand-side-name.
 * @param lhs_e. Input. Ending index of left-hand-side-name (should be one more than last index to compare)
 * @param rhs. Input. Right-hand-side Name.
 * @param rhs_b. Input. Beginning index of right-hand-side-name.
 * @param rhs_e. Input. Ending index of right-hand-side-name (should be one more than last index to compare)
 * @return 0 if @p lhs from lhs_b to lhs_e-1 == @p rhs from rhs_b to rhs_e-1.
 */
int
ndn_name_compare_sub_names(const ndn_name_t* lhs, int lhs_b, int lhs_e,
			   const ndn_name_t* rhs, int rhs_b, int rhs_e);

/**
 * Compare two Name based on the canonical order, to see whether a name is the prefix
 * of another.
 * @param lhs. Input. Left-hand-side Name.
 * @param rhs. Input. Right-hand-side Name.
 * @return 0 if @p lhs is the prefix of @p rhs.
 */
int
ndn_name_is_prefix_of(const ndn_name_t* lhs, const ndn_name_t* rhs);

/**
 * Compare two encoded Names.
 * @param lhs_block_value. Input. Left-hand-side encoded Name block value.
 * @param lhs_block_size. Input. Left-hand-side encoded Name block size.
 * @param rhs_block_value. Input. Right-hand-side encoded Name block value.
 * @param rhs_block_size. Input. Right-hand-side encoded Name block size.
 * @return 0 if @p lhs == @p rhs.
 * @return 1, if @p lhs > @p rhs and @p rhs is not a prefix of @p lhs.
 * @return 2, if @p lhs > @p rhs and @p rhs is a proper prefix of @p lhs.
 * @return -1, if @p lhs < @p rhs and @p lhs is not a prefix of @p rhs.
 * @return -2, if @p lhs < @p rhs and @p lhs is a proper prefix of @p rhs.
 */
int
ndn_name_compare_block(const uint8_t* lhs_block_value, uint32_t lhs_block_size,
                       const uint8_t* rhs_block_value, uint32_t rhs_block_size);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_NAME_H
