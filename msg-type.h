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
 * @brief   Message type for internal communication between NDN thread
 *          and NDN App thread.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_MSG_TYPE_H_
#define NDN_MSG_TYPE_H_

#ifdef __cplusplus
extern "C" {
#endif

#define NDN_APP_MSG_TYPE_TERMINATE  (0x0300)

#define NDN_APP_MSG_TYPE_TIMEOUT    (0x0301)

#define NDN_APP_MSG_TYPE_DATA       (0x0302)

#define NDN_APP_MSG_TYPE_INTEREST   (0x0303)

#define NDN_APP_MSG_TYPE_ADD_FACE   (0x0304)

#define NDN_APP_MSG_TYPE_REMOVE_FACE   (0x0305)

#define NDN_APP_MSG_TYPE_ADD_FIB    (0x0306)

#define NDN_APP_MSG_TYPE_ADD_STRATEGY  (0x0309)

#define NDN_PIT_MSG_TYPE_TIMEOUT    (0x0307)

#define NDN_L2_FRAG_MSG_TYPE_TIMEOUT   (0x0308)

#ifdef __cplusplus
}
#endif

#endif /* NDN_MSG_TYPE_H_ */
/** @} */
