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

typedef struct ndn_fragmenter {
  const uint8_t* original;
  uint32_t original_size;
  uint32_t fragment_max_size;
  uint8_t total_seq;
  uint16_t frag_identifier;

  uint32_t offset;
  uint8_t seq; // NEXT seq to be used
} ndn_fragmenter_t;

// typedef struct ndn_assembler {
//   uint8_t* original;
//   uint16_t frag_identifier;

//   uint32_t offset;
//   uint8_t seq; // NEXT seq to be received
// } ndn_assembler_t;

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
  *fragmented = fragmenter->seq;
  if (fragmenter->seq < fragmenter->total_seq)
    *fragmented |= NDN_FRAG_MF_MASK;
  *fragmented |= NDN_FRAG_HB_MASK;
  *(fragmented + 1) = (fragmenter->frag_identifier >> 8) & 0xFF;
  *(fragmented + 2) = fragmenter->frag_identifier & 0xFF;

  // payload
  int size = (fragmenter->seq == fragmenter->total_seq)?
    fragmenter->original_size - fragmenter->offset: fragmenter->fragment_max_size - 3;
  memcpy(fragmented + 3, &fragmenter->original[offset], size);

  // update state
  fragmenter->seq++;
  fragmenter->offset += size;
  return 0;
}


#endif // NDN_ENCODING_FRAGMENTATION_H
