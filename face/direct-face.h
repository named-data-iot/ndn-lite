/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_DIRECT_FACE_H_
#define FORWARDER_DIRECT_FACE_H_

#define NDN_DIRECT_FACE_CB_ENTRY_SIZE 5

#include "../forwarder/face.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Direct Face is a face implementation for single-thread program where
 * application and forwarder are in the same thread
 *
 * In normal case, the logic of NDN face between app and forwarder is
 *  +------+            +--------+
 *  |app {face} <---> {face} fwd |
 *  +------+            +--------+
 *
 * With direct face, the logic is greatly simplified in single-thread scenario
 *  +------+        +--------+
 *  | app {direct face} fwd  |
 *  +------+        +--------+
 *
 * In other words, direct face is an app face and a forwarder face, thus direct
 * face provides APIS for both sides:
 *    APIs for app:
 *      * direct_face_express_interest
 *      * direct_face_register_prefix
 *    APIs for forwarder:
 *      * direct_face_send
 *      * direct_face_receive
 */

/**
 * ndn_on_data_callback is a function pointer to the on data function.
 * After invoking the function, the face will process the incoming response packet.
 * @param data. Input. The incoming data TLV buffer.
 * @param data_size. Input. Size of incoming data TLV buffer.
 * @return 0 if there is no error.
 */
typedef int (*ndn_on_data_callback)(const uint8_t* data, uint32_t data_size);

/**
 * ndn_interest_timeout_callback is a function pointer to the interest timeout function.
 * After invoking the function, the face will trigger the interest timeout event.
 * @param interest. Input. The expired interest TLV.
 * @param interest_size. Input. Size of expired interest TLV.
 * @return 0 if there is no error.
 */
typedef int (*ndn_interest_timeout_callback)(const uint8_t* interest, uint32_t interest_size);

/**
 * ndn_on_interest_callback is a function pointer to the on interest function.
 * After invoking the function, the face will process the incoming interest packet.
 * @param interest. Input. The incoming interest TLV buffer.
 * @param interest_size. Input. Size of incoming interest TLV buffer.
 * @return 0 if there is no error.
 */
typedef int (*ndn_on_interest_callback)(const uint8_t* interest, uint32_t interest_size);

/**
 * The structure to represent a direct face callback entry
 */
typedef struct ndn_face_cb_entry {
  /**
   * The interest name of callback entry.
   */
  ndn_name_t interest_name;
  /**
   * Flag to represent current callback entry is a registered prefix.
   */
  uint8_t is_prefix;
  /**
   * on_data callback.
   */
  ndn_on_data_callback on_data;
  /**
   * on_timeout callback.
   */
  ndn_interest_timeout_callback on_timeout;
  /**
   * on_interest callback.
   */
  ndn_on_interest_callback on_interest;
} ndn_face_cb_entry_t;

/**
 * The structure to represent a direct face.
 */
typedef struct ndn_direct_face {
  /**
   * The inherited interface abstraction.
   */
  ndn_face_intf_t intf;
  /**
   * List of callback entries.
   */
  ndn_face_cb_entry_t cb_entries[NDN_DIRECT_FACE_CB_ENTRY_SIZE];
} ndn_direct_face_t;

/**
 * Construct the direct face and initialize its state.
 * @param face_id. Input. The face id to identity the direct face.
 * @return the pointer to the constructed direct face.
 */
ndn_direct_face_t*
ndn_direct_face_construct(uint16_t face_id);

/**
 * Let the direct face express an interest.
 * @param prefix_name. Input. Prefix name to identify the callback entry.
 * @param interest. Input. The wire format Interest received by the direct face.
 * @param interest_size. Input. The size of the wire format Interest.
 * @param on_data. Input. on_data function pointer of the callback entry.
 * @param on_interest_timeout. Input. on_interest_timeout function pointer of the callback entry.
 * @return 0 if there is no error.
 */
int
ndn_direct_face_express_interest(const ndn_name_t* prefix_name,
                                 uint8_t* interest, uint32_t interest_size,
                                 ndn_on_data_callback on_data,
                                 ndn_interest_timeout_callback on_interest_timeout);

/**
 * Let the direct face register a prefix on the FIB.
 * @param interest_name. Input. Prefix name to identify the callback entry.
 * @param on_interest. Input. on_interest function pointer of the callback entry.
 * @return 0 if there is no error.
 */
int
ndn_direct_face_register_prefix(const ndn_name_t* interest_name,
                                ndn_on_interest_callback on_interest);

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_DIRECT_FACE_H_
