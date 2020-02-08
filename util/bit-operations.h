/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef UTIL_BIT_OPERATIONS_H_
#define UTIL_BIT_OPERATIONS_H_

#include <stddef.h>
#include <stdint.h>

/* a=target variable, b=bit number to act upon 0-n */
#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1ULL<<(b)))
#define BIT_FLIP(a,b) ((a) ^= (1ULL<<(b)))
#define BIT_CHECK(a,b) (!!((a) & (1ULL<<(b))))

/* x=target variable, y=mask */
#define BITMASK_SET(x,y) ((x) |= (y))
#define BITMASK_CLEAR(x,y) ((x) &= (~(y)))
#define BITMASK_FLIP(x,y) ((x) ^= (y))
#define BITMASK_CHECK_ALL(x,y) (((x) & (y)) == (y))
#define BITMASK_CHECK_ANY(x,y) ((x) & (y))

typedef uint64_t ndn_bitset_t;

#define LEAST_SIG_BIT(x) ((x) & (-(x)))

static inline ndn_bitset_t bitset_set(ndn_bitset_t set, size_t val){
  return (set | (((ndn_bitset_t)1) << ((ndn_bitset_t)val)));
}

static inline ndn_bitset_t bitset_unset(ndn_bitset_t set, size_t val){
  return (set & ~(((ndn_bitset_t)1) << ((ndn_bitset_t)val)));
}

static inline size_t bitset_log2(ndn_bitset_t val){
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_ctz(val);
#else
  size_t n = 0;
  if((x & 0x00000000FFFFFFFFllu) == 0){
    n += 32;
    val >>= 32llu;
  }
  if((x & 0x000000000000FFFFllu) == 0){
    n += 16;
    val >>= 16llu;
  }
  if((x & 0x00000000000000FFllu) == 0){
    n += 8;
    val >>= 8llu;
  }
  if((x & 0x000000000000000Fllu) == 0){
    n += 4;
    val >>= 4llu;
  }
  if((x & 0x0000000000000003llu) == 0){
    n += 2;
    val >>= 2llu;
  }
  if((x & 0x0000000000000001llu) == 0){
    n += 1;
  }
  return n;
#endif
}

static inline size_t bitset_pop_least(ndn_bitset_t* val){
  ndn_bitset_t lsbit = LEAST_SIG_BIT(*val);
  size_t ret = bitset_log2(lsbit);
  *val &= ~lsbit;
  return ret;
}

#endif // UTIL_BIT_OPERATIONS_H_