//
//  memory-pool.h
//  riot-forwarder
//
//  Created by UCLA on 11/2/18.
//  Copyright © 2018 UCLA. All rights reserved.
//

#ifndef memory_pool_h
#define memory_pool_h

// This value should be larger than Data and Interest
#define NDN_POOL_BLOCK_SIZE 2560
#define NDN_POOL_BLOCK_CNT 3

// Memory pool deals with temp large memory like Interest and Data.
// Memory blocks are allocated in fixed size

int
ndn_memory_pool_init(void);

uint8_t*
ndn_memory_pool_alloc(void);

int
ndn_memory_pool_free(void* ptr);

#endif /* memory_pool_h */
