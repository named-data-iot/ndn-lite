/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_FACE_TABLE_H_
#define FORWARDER_FACE_TABLE_H_

#include "face.h"
#include "../ndn-constants.h"

/** @defgroup NDNFwdFaceTab Face Table
 * @brief Face Table.
 * @ingroup NDNFwd
 * @{
 */

/** Face Table.
 *
 * It assigns an unique ID to all faces.
 */
typedef struct ndn_face_table{
  ndn_table_id_t capacity;

  /** All registered faces.
   * NULL for empty entries.
   */
  ndn_face_intf_t* slots[];
}ndn_face_table_t;

/** The memory reserved for FaceTable.
 * @param[in] entry_count Maximum number of entries.
 */
#define NDN_FACE_TABLE_RESERVE_SIZE(entry_count) \
  (sizeof(ndn_face_table_t) + sizeof(ndn_face_intf_t*) * (entry_count))

/** Initialize FaceTable at specified memory space.
 * @param[in, out] memory Memory reserved for FaceTable.
 * @param[in] capacity Maximum number of entries.
 */
void
ndn_facetab_init(void* memory, ndn_table_id_t capacity);

/** Register a face and assign an ID to it.
 * @param[in, out] self FaceTable.
 * @param[in] face The face to register.
 * @return The ID for @c face if succeeded. #NDN_INVALID_ID if FaceTable is full.
 * @pre @c face should be just created. The constructor should call this function.
 */
ndn_table_id_t
ndn_facetab_register(ndn_face_table_t* self, ndn_face_intf_t* face);

/** Unregister a face from FaceTable only.
 * @param[in, out] self FaceTable.
 * @param[in] face The face to unregister.
 * @pre <tt>id < self->ndn_face_table_t#capacity</tt>
 */
void
ndn_facetab_unregister(ndn_face_table_t* self, ndn_table_id_t id);

/*@}*/

#endif // FORWARDER_FACE_TABLE_H_
