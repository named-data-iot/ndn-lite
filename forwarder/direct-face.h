/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_DIRECT_FACE_H_
#define FORWARDER_DIRECT_FACE_H_

#include "../encode/ndn-constants.h"
#include "../encode/data.h"
#include "../encode/interest.h"
#include <inttypes.h>

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

typedef int (*ndn_on_data_callback)(const uint8_t* data, uint32_t data_size);
typedef int (*ndn_interest_timeout_callback)(const uint8_t* interest, uint32_t interest_size);
typedef int (*ndn_on_interest_callback)(const uint8_t* interest, uint32_t interest_size);

typedef struct ndn_face_cb_entry {
  ndn_name_t interest_name;
  uint8_t is_prefix;

  ndn_on_data_callback on_data;
  ndn_interest_timeout_callback on_timeout;
  ndn_on_interest_callback on_interest;
} ndn_face_cb_entry_t;

#define NDN_DIRECT_FACE_CB_ENTRY_SIZE 5

typedef struct ndn_direct_face {
  ndn_face_intf_t intf;
  ndn_face_cb_entry_t cb_entries[NDN_DIRECT_FACE_CB_ENTRY_SIZE];
} ndn_direct_face_t;

void
ndn_direct_face_construct(ndn_direct_face_t* self, uint16_t face_id);

int
ndn_direct_face_express_interest(ndn_direct_face_t* self, const ndn_name_t* prefix_name,
                                 uint8_t* interest, uint32_t interest_size,
                                 ndn_on_data_callback on_data,
                                 ndn_interest_timeout_callback on_interest_timeout);

int
ndn_direct_face_register_prefix(ndn_direct_face_t* self, const ndn_name_t* interest_name,
                                ndn_on_interest_callback on_interest);

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_DIRECT_FACE_H_
