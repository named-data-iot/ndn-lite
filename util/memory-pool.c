/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "memory-pool.h"

#define MEMORY_BLOCK_USED NULL

#pragma pack(1)
typedef struct memory_block
{
  // next make a linked-list of free blocks
  struct memory_block * next;
  uint8_t buf[];
} memory_block_t, *pmemory_block_t;
#pragma pack()

void
ndn_memory_pool_init(void* pool, size_t block_size, size_t block_count)
{
  int i;
  pmemory_block_t *first = (pmemory_block_t*)pool;
  size_t ptr_sz = sizeof(pmemory_block_t*);
  size_t memblk_sz = sizeof(memory_block_t) + block_size;
  pmemory_block_t cur = (pmemory_block_t)((uint8_t*)pool + ptr_sz);
  pmemory_block_t pre;
  
  pre = MEMORY_BLOCK_USED;
  for (i = 0; i < (int) block_count; i ++) {
    cur->next = pre;
    pre = cur;
    cur = (pmemory_block_t)((uint8_t*)cur + memblk_sz);
  }
  *first = pre;
}

uint8_t*
ndn_memory_pool_alloc(void* pool)
{
  pmemory_block_t *first = (pmemory_block_t*)pool;
  if (*first == MEMORY_BLOCK_USED) {
    return NULL;
  }
  pmemory_block_t ret = *first;
  *first = ret->next;
  ret->next = MEMORY_BLOCK_USED;
  return &ret->buf[0];
}

int
ndn_memory_pool_free(void* pool, void* ptr)
{
  pmemory_block_t *first = (pmemory_block_t*)pool;
  pmemory_block_t base_addr;

  if (ptr == NULL) {
    return -1;
  }
  base_addr = (memory_block_t*)((uint8_t*)ptr - ((size_t)&((memory_block_t*)NULL)->buf[0]));
  if (base_addr->next != MEMORY_BLOCK_USED) {
    return -1;
  }
  base_addr->next = *first;
  *first = base_addr;
  return 0;
}
