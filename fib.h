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
 * @brief   NDN FIB implementation.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_FIB_H_
#define NDN_FIB_H_

#include "encoding/shared-block.h"
#include "face-table.h"

#include <kernel_types.h>
#include <xtimer.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Type to represent the FIB entry.
 */
typedef struct ndn_fib_entry {
    struct ndn_fib_entry *prev;
    struct ndn_fib_entry *next;
    ndn_shared_block_t* prefix;
    int plen;

    // List of out-going faces
    _face_list_entry_t *face_list;
    int face_list_size;
} ndn_fib_entry_t;


/**
 * @brief   Adds a routing entry to FIB.
 *
 * @param[in]  prefix     Name prefix of the route. Will be "moved" into
 *                        the FIB entry, or released if an entry with the
 *                        same name already exists.
 * @param[in]  face_id    PID of the face where this route points to.
 * @param[in]  face_type  Type of the face where this route points to.
 *
 * @return  0, if success.
 * @return  -1, if cannot add FIB entry.
 * @return  -1, if @p prefix is NULL.
 */
int ndn_fib_add(ndn_shared_block_t* prefix, kernel_pid_t face_id, int face_type);

/**
 * @brief   Looks up the FIB to find an entry with longest matching prefix.
 *
 * @param[in]  name    TLV block of the name.
 *
 * @return  Pointer to the matching FIB entry, if success.
 * @return  NULL, if no matching FIB entry is found.
 * @retrun  NULL, if @p name is NULL or invalid.
 */
ndn_fib_entry_t* ndn_fib_lookup(ndn_block_t* name);

/**
 * @brief   Removes the face from all FIB entries.
 *
 * @param[in]   face_id   PID of the face to be removed.
 */
void ndn_fib_remove_by_face(kernel_pid_t face_id);

/**
 * @brief    Initializes the FIB table.
 */
void ndn_fib_init(void);

#ifdef __cplusplus
}
#endif

#endif /* NDN_PIT_H_ */
/** @} */
