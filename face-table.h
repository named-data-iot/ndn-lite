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
 * @brief   NDN Face table implementation. Mostly a wrapper around utlist.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_FACE_TABLE_H_
#define NDN_FACE_TABLE_H_

#include <kernel_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NDN_FACE_ENTRIES_NUMOF
/**
 * @brief Number of max. faces in the face table
 */
#define NDN_FACE_ENTRIES_NUMOF (10)
#endif

typedef struct _face_list_entry {
    kernel_pid_t id;  /**< ID of the incoming face */
    int type;         /**< type of the incoming face */
} _face_list_entry_t;


/**
 * @brief Type to represent a Face entry.
 */
typedef struct ndn_face_entry {
    struct ndn_face_entry* prev;
    struct ndn_face_entry* next;
    kernel_pid_t id;
    int type;
} ndn_face_entry_t;

enum {
    NDN_FACE_UNDEF,  // undefined face
    NDN_FACE_APP,    // local app face
    NDN_FACE_NETDEV, // net device face
};

/**
 * @brief  Gets the current size of the face table.
 *
 * @return Size of the face table.
 * @return 0, if face table is empty.
 */
int ndn_face_table_size(void);

/**
 * @brief      Finds the face entry with a specific id.
 *
 * @param[in]  id    Face id to search for.
 *
 * @return     Pointer to the entry, if found.
 * @return     NULL, if such entry does not exist.
 */
ndn_face_entry_t* ndn_face_table_find(kernel_pid_t id);


/**
 * @brief      Adds an entry to the face table.
 *
 * @param[in]  id     Face id.
 * @param[in]  type   Face type.
 *
 * @return     0, if success.
 * @return     -1, if the face id already exists.
 * @retrun     -1, if out of memory.
 */
int ndn_face_table_add(kernel_pid_t id, int type);

/**
 * @brief      Removes the face entry with a specific id.
 *
 * @param[in]  id    Face id to remove.
 *
 * @return     0, if success.
 * @return     -1, if such entry does not exist.
 */
int ndn_face_table_remove(kernel_pid_t id);

/**
 * @brief    Initializes the face table.
 */
void ndn_face_table_init(void);


#ifdef __cplusplus
}
#endif

#endif /* NDN_FACE_TABLE_H_ */
/** @} */
