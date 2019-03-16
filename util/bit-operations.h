/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */
#ifndef UTIL_BIT_OPERATIONS_H_
#define UTIL_BIT_OPERATIONS_H_

#include <stddef.h>
#include <stdint.h>

typedef uint64_t ndn_bitset_t;

#define LEAST_SIG_BIT(x) ((x) & (-(x)))

static inline ndn_bitset_t bitset_set(ndn_bitset_t set, size_t val){
  return (set | (((ndn_bitset_t)1) << ((ndn_bitset_t)val)));
}

static inline ndn_bitset_t bitset_unset(ndn_bitset_t set, size_t val){
  return (set & ~(((ndn_bitset_t)1) << ((ndn_bitset_t)val)));
}

static inline size_t bitset_log2(ndn_bitset_t val){
  return __builtin_ctz(val);
}

#endif // UTIL_BIT_OPERATIONS_H_