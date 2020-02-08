/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_MSG_QUEUE_H_
#define FORWARDER_MSG_QUEUE_H_

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**@defgroup NDNUtil
 */

/** @defgroup NDNUtilMsqQueue Message Queue
 * @ingroup NDNUtil
 *
 * Message queue of the forwarder.
 * @{
 */

/** The size of message queue in bytes.
 */
#define NDN_MSGQUEUE_SIZE 4096

#pragma pack(1)
struct ndn_msg;
#pragma pack()

/** The callback function of message.
 *
 * @param[in, out] self The object to receive this message.
 * @param[in] param_length [Optional] The length of the @c param.
 * @param[in] param [Optional] Point to a raw memory in size @c param_length.
 */
typedef void(*ndn_msg_callback)(void *self,
                                size_t param_length,
                                void *param);

/** Init the message queue.
 */
void
ndn_msgqueue_init(void);

/** Post a message to the queue.
 * @param[in] target The object to receive this message.
 * @param[in] reason The message callback function.
 * @param[in] length [Optional] The length of parameters @c param.
 * @param[in] param  [Optional] The parameters of this message.
 *                   Its context will be copied into the queue.
 * @return An pointer to cancel the message. NULL if failed.
 */
struct ndn_msg*
ndn_msgqueue_post(void *target,
                  ndn_msg_callback reason,
                  size_t param_length,
                  void *param);

/** Dispatch a message on the top of the queue.
 *
 * Call the message by <tt> reason(target, param_length, param) </tt>.
 * @retval true One message dispatched.
 * @retval false The queue is empty. Do nothing.
 */
bool
ndn_msgqueue_dispatch(void);

/** Return if the messque queue is empty.
 * @retval true Empty.
 * @retval false Not empty.
 * @note This function will defragment the queue if it's empty.
 */
bool
ndn_msgqueue_empty(void);

/** Dispatch current messages.
 *
 * Process all messages currently in the queue.
 * New messages posted during this function will not be dispatched.
 * @warning Calling this function in any callback functions is not allowed.
 */
void
ndn_msgqueue_process(void);

/** Cancel a posted message.
 *
 * Please make sure the pointer is correct and it's used before dispatch.
 * @param[in] msg Pointer to message
 */
void
ndn_msgqueue_cancel(struct ndn_msg* msg);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // #define FORWARDER_MSG_QUEUE_H_
