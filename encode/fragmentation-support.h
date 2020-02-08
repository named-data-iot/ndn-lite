/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_FRAGMENTATION_SUPPORT_H
#define NDN_ENCODING_FRAGMENTATION_SUPPORT_H

#include "../ndn-constants.h"
#include "../ndn-error-code.h"
#include <inttypes.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * NDN-Lite reuses the ndn-riot fragmentation header (3 bytes header)
 *
 *    0           1           2
 *    0 1 2  3    8         15           23
 *    +-+-+--+----+----------------------+
 *    |1|X|MF|Seq#|    Identification    |
 *    +-+-+--+----+----------------------+
 *
 *    First bit: header bit, always 1 (indicating the fragmentation header)
 *    Second bit: reserved, always 0
 *    Third bit: MF bit
 *    4th to 8th bit: sequence number (5 bits, encoding up to 31 fragments)
 *    9th to 24th bit: identification (2-byte random number)
 */

/**
 * The structure to keep the state when doing fragmentation.
 */
typedef struct ndn_fragmenter {
  /**
   * The buffer to keep the original packet.
   */
  const uint8_t* original;
  /**
   * The size of the original packet.
   */
  uint32_t original_size;
  /**
   * The max size of each fragment.
   * This value is obtained from protocol-specific MTU.
   */
  uint32_t fragment_max_size;
  /**
   * The identifier of the fragments.
   */
  uint16_t frag_identifier;
  /**
   * The total number of frags to be generated
   */
  uint32_t total_frag_num;
  /**
   * The offset before which the original packet has been fragmented.
   */
  uint32_t offset;
  /**
   * The counter indicating how many frags have been generated.
   */
  uint32_t counter;
} ndn_fragmenter_t;


/**
 * Init a fragmenter.
 * @param fragmenter. Output. The fragmenter to be inited.
 * @param original. Input. The original packet buffer.
 * @param original_size. Input. The size of the original packet buffer.
 * @param fragment_max_size. Input. The max size of each fragment.
 *        This value is obtained from protocol-specific MTU.
 * @param frag_identifier. Input. The identifier of the fragments
 *        generated from the original packet.
 */
static inline void
ndn_fragmenter_init(ndn_fragmenter_t* fragmenter, const uint8_t* original, uint32_t original_size,
                    uint32_t fragment_max_size, uint16_t frag_identifier)
{
  fragmenter->original = original;
  fragmenter->original_size = original_size;
  fragmenter->fragment_max_size = fragment_max_size;
  fragmenter->frag_identifier = frag_identifier;

  fragmenter->total_frag_num = fragmenter->original_size / (fragment_max_size - 3);
  int rem = fragmenter->original_size % (fragment_max_size - 3);
  if (rem != 0)
    fragmenter->total_frag_num += 1;
  fragmenter->offset = 0;
  fragmenter->counter = 0;
}

/**
 * Generate one fragmented packet.
 * @param fragmenter. Input/Output. The fragmenter used to keep the original packet and the state.
 * @param fragmented. Output. The buffer to keep the fragmented packet.
 *        The buffer size should at least be the fragmenter->fragment_max_size.
 * @return 0 if there is no error.
 */
static inline int
ndn_fragmenter_fragment(ndn_fragmenter_t* fragmenter, uint8_t* fragmented)
{
  if (fragmenter->counter == fragmenter->total_frag_num)
    return NDN_FRAG_NO_MORE_FRAGS;

  memset(fragmented, 0, fragmenter->fragment_max_size);

  uint8_t is_last = (fragmenter->counter == fragmenter->total_frag_num - 1)? 1 : 0;
  uint8_t seq = fragmenter->counter % (NDN_FRAG_MAX_SEQ_NUM + 1);

  // header
  fragmented[0] = seq;
  if (is_last)
    fragmented[0] |= NDN_FRAG_MF_MASK;
  fragmented[0] |= NDN_FRAG_HB_MASK;
  fragmented[1] = (fragmenter->frag_identifier >> 8) & 0xFF;
  fragmented[2] = fragmenter->frag_identifier & 0xFF;

  // payload
  int size = (is_last)?
    fragmenter->original_size - fragmenter->offset: fragmenter->fragment_max_size - 3;
  memcpy(&fragmented[3], &fragmenter->original[fragmenter->offset], size);

  // update state
  fragmenter->counter++;
  fragmenter->offset += size;
  return 0;
}

/**
 * The structure to keep the state when assembling fragments.
 */
typedef struct ndn_frag_assembler {
  /**
   * The buffer to keep the original packet.
   */
  uint8_t* original;
  /**
   * The size of the buffer to keep the original packet.s
   */
  uint32_t original_max_size;
  /**
   * The identifier of the fragments.
   */
  uint16_t frag_identifier;
  /**
   * The offset before which the original packet has been assembled.
   */
  uint32_t offset;
  /**
   * Next sequence number of the fragment to be received.
   */
  uint8_t seq;
  /**
   * A flag used to check whether the assembling is finished.
   */
  uint8_t is_finished;
} ndn_frag_assembler_t;

/**
 * Init an assembler.
 * @param assembler. Output. The assembler to be inited.
 * @param original. Input. The buffer used to keep the assembled packet.
 * @param original_max_size. Input. The size of the buffer used to keep the assembled packet.
 */
static inline void
ndn_frag_assembler_init(ndn_frag_assembler_t* assembler, uint8_t* original, uint32_t original_max_size)
{
  assembler->original = original;
  assembler->original_max_size = original_max_size;
  assembler->frag_identifier = 0;
  assembler->offset = 0;
  assembler->seq = 0;
  assembler->is_finished = 0;
}

/**
 * Assemble a fragment into the assembler.
 * @param assembler. Output. The assembler used to keep the assembled packet and the state.
 * @param frag. Input. The fragment packet buffer.
 * @param fra_size. Input. The size of the fragment packet buffer.
 * @return 0 if there is no error.
 */
static inline int
ndn_frag_assembler_assemble_frag(ndn_frag_assembler_t* assembler, uint8_t* frag, uint32_t fra_size)
{
  int first_time = (assembler->offset == 0)? 1 : 0;
  // get seq
  uint8_t seq = frag[0] & NDN_FRAG_SEQ_MASK;
  if (seq != assembler->seq)
    return NDN_FRAG_OUT_OF_ORDER;
  assembler->seq += 1;
  if (assembler->seq == NDN_FRAG_MAX_SEQ_NUM + 1)
    assembler->seq = 0;

  // get identifier
  uint16_t id = ((uint16_t)frag[1] << 8) + (uint16_t)frag[2];
  if (assembler->frag_identifier != id && first_time == 0)
    return NDN_FRAG_WRONG_IDENTIFIER;
  if (first_time)
    assembler->frag_identifier = id;

  if (assembler->original_max_size < assembler->offset + fra_size - 3)
    return NDN_OVERSIZE;

  memcpy(&assembler->original[assembler->offset], &frag[3], fra_size - 3);
  assembler->offset += fra_size - 3;

  // get MF bit
  uint8_t mf = frag[0] & NDN_FRAG_MF_MASK;
  if (mf == NDN_FRAG_MF_MASK) {
    // no more frags
    assembler->is_finished = 1;
  }
  return 0;
}

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_FRAGMENTATION_SUPPORT_H
