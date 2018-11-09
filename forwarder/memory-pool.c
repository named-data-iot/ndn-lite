/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "../encode/ndn_constants.h"
#include "../encode/interest.h"
#include "../encode/data.h"
#include "memory-pool.h"

#define MEMORY_BLOCK_USED 0xFF

typedef struct memory_block
{
  // next make a linked-list of free blocks
  uint8_t next;
  uint8_t buf[NDN_POOL_BLOCK_SIZE];
} memory_block_t;
static memory_block_t memory_pool[NDN_POOL_BLOCK_CNT];
static uint8_t memory_pool_first;

int
ndn_memory_pool_init()
{
  if(NDN_POOL_BLOCK_SIZE < sizeof(ndn_interest_t) ||
     NDN_POOL_BLOCK_SIZE < sizeof(ndn_data_t))
  {
    return -1;
  }
  
  memory_pool_first = NDN_POOL_BLOCK_CNT - 1;
  for(int i = 0; i < NDN_POOL_BLOCK_CNT; i ++)
  {
    memory_pool[i].next = i - 1;
  }
  memory_pool[0].next = MEMORY_BLOCK_USED;
  
  return 0;
}

uint8_t*
ndn_memory_pool_alloc()
{
  if(memory_pool_first == MEMORY_BLOCK_USED)
  {
    return NULL;
  }
  uint8_t ret = memory_pool_first;
  memory_pool_first = memory_pool[ret].next;
  memory_pool[ret].next = MEMORY_BLOCK_USED;
  return &memory_pool[ret].buf[0];
}

int
ndn_memory_pool_free(void* ptr)
{
  memory_block_t* base_addr;
  
  if(ptr == NULL)
  {
    return -1;
  }
  base_addr = (memory_block_t*)((uint8_t*)ptr - ((size_t)&((memory_block_t*)NULL)->buf[0]));
  if(base_addr->next != MEMORY_BLOCK_USED)
  {
    return -1;
  }
  base_addr->next = memory_pool_first;
  memory_pool_first = base_addr - memory_pool;
  return 0;
}
