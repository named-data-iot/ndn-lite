/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ENCODING_FRAGMENTATION_H
#define NDN_ENCODING_FRAGMENTATION_H

/*
 * Reuse the ndn-riot fragmentation header (3 bytes header)
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

#define NDN_FRAG_HDR_LEN 3 // Size of the NDN L2 fragmentation header
#define NDN_FRAG_HB_MASK 0x80 // 1000 0000
#define NDN_FRAG_MF_MASK 0x20 // 0010 0000
#define NDN_FRAG_SEQ_MASK 0x1F // 0001 1111
#define NDN_FRAG_MAX_SEQ_NUM 30

typedef struct ndn_fragmenter {
  const uint8_t* original;
  uint32_t original_size;
  uint32_t fragment_max_size;
  uint8_t total_seq;
  uint16_t frag_identifier;

  uint32_t offset;
  uint8_t seq; // NEXT seq to be used
} ndn_fragmenter_t;

static inline void
ndn_fragmenter_init(ndn_fragmenter_t* fragmenter, const uint8_t* original, uint32_t original_size,
                    uint32_t fragment_max_size, uint16_t frag_identifier)
{
  fragmenter->original = original;
  fragmenter->original_size = original_size;
  fragmenter->fragment_max_size = fragment_max_size;
  fragmenter->total_seq = fragmenter->original_size / (fragment_max_size - 3);
  fragmenter->total_seq += 1;
  fragmenter->frag_identifier = frag_identifier;

  fragmenter->offset = 0;
  fragmenter->seq = 0;
}

static inline uint32_t
ndn_fragmenter_probe_required_size(ndn_fragmenter_t* fragmenter)
{
  return fragmenter->total_seq*3 + fragmenter->original_size;
}

// generate ONE fragmented packet
// fragmented's size should at least be the fragment_max_size
static inline int
ndn_fragmenter_fragment(ndn_fragmenter_t* fragmenter, uint8_t* fragmented)
{
  if (fragmenter->seq > fragmenter->total_seq)
    return NDN_ERROR_OVERSIZE;

  // header
  fragmented[0] = fragmenter->seq;
  if (fragmenter->seq < fragmenter->total_seq)
    fragmented[0] |= NDN_FRAG_MF_MASK;
  fragmented[0] |= NDN_FRAG_HB_MASK;
  fragmented[1] = (fragmenter->frag_identifier >> 8) & 0xFF;
  fragmented[2] = fragmenter->frag_identifier & 0xFF;

  // payload
  int size = (fragmenter->seq == fragmenter->total_seq)?
    fragmenter->original_size - fragmenter->offset: fragmenter->fragment_max_size - 3;
  memcpy(fragmented + 3, &fragmenter->original[offset], size);

  // update state
  fragmenter->seq++;
  if (fragmenter->seq == NDN_FRAG_MAX_SEQ_NUM + 1)
    fragmenter == 0;
  fragmenter->offset += size;
  return 0;
}

typedef struct ndn_frag_assembler {
  uint8_t* original;
  uint32_t original_max_size;
  uint16_t frag_identifier;

  uint32_t offset;
  uint8_t seq; // NEXT seq to be received
  uint8_t is_finished; // used to check whether the assembling is finished
} ndn_frag_assembler_t;

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

static inline int
ndn_frag_assembler_assemble_frag(ndn_frag_assembler_t* assembler, uint8_t* frag, uint32_t fra_size)
{

  int first_time = (assembler->offset == 0)? 1 : 0;
  // get seq
  uint8_t seq = frag[0] & NDN_FRAG_SEQ_MASK;
  if (seq != assembler->seq)
    return NDN_ERROR_FRAG_OUT_OF_ORDER;
  assembler->seq += 1;
  if (assembler->seq == NDN_FRAG_MAX_SEQ_NUM + 1)
    assembler->seq = 0;

  // get identifier
  uint16_t id = (uint16_t)frag[1] << 8 + (uint16_t)frag[2];
  if (assembler->frag_identifier != id && first_time == 0)
    return NDN_ERROR_FRAG_WRONG_IDENTIFIER;
  if (first_time)
    assembler->frag_identifier = id;

  memcpy(assembler->original[assembler->offset], &frag[3], fra_size - 3);

  // get MF bit
  uint8_t mf = frag[0] & NDN_FRAG_MF_MASK;
  if (mf == 0) {
    // no more frags
    assembler->is_finished = 1;
  }
  return 0;
}

#endif // NDN_ENCODING_FRAGMENTATION_H
