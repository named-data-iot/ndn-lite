/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ndn    NDN packet processing
 * @ingroup     net
 * @brief       NDN packet sending and receiving.
 * @{
 *
 * @file
 * @brief   NDN content store implementation.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_CS_H_
#define NDN_CS_H_

#include "encoding/shared-block.h"

#include <kernel_types.h>
//#include <xtimer.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ndn_cs_entry {
    struct ndn_cs_entry *prev;
    struct ndn_cs_entry *next;
    ndn_shared_block_t *data;
    //TODO: add freshness timer
} ndn_cs_entry_t;

/**
 * @brief   Adds a data block to the CS.
 * @details Will make a copy of the shared block.
 *
 * @oaram[in]  data    Data block to add.
 *
 * @return  0, if success.
 * @return  -1, if out of memory.
 */
int ndn_cs_add(ndn_shared_block_t* data);

/**
 * @brief   Macthes interest in the CS.
 *
 * @param[in]  interest   Interest block to match.
 *
 * @return  Shared pointer to the data block. Caller is responsible for
 *          releasing the pointer.
 * @return  NULL, if no match is found.
 * @retrun  NULL, if @p interest is invalid.
 */
ndn_shared_block_t* ndn_cs_match(ndn_block_t* interest);

/**
 * @brief    Initializes the content store.
 */
void ndn_cs_init(void);


#ifdef __cplusplus
}
#endif

#endif /* NDN_CS_H_ */
/** @} */
