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
 * @brief   Interface between NDN and NDN app (aka. client library).
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_APP_H_
#define NDN_APP_H_

#include "encoding/name.h"
#include "encoding/block.h"
#include "encoding/shared-block.h"

#include "forwarding-strategy.h"

#include <kernel_types.h>
#include <xtimer.h>
#include <net/gnrc/pktbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Return code for the callbacks.
 */
enum {
    NDN_APP_ERROR = -1,    /**< app should stop due to an error */
    NDN_APP_STOP = 0,      /**< app should stop after this callback */
    NDN_APP_CONTINUE = 1,  /**< app should continue after this callback */
};

/**
 * @brief  Type for the on_data consumer callback.
 */
typedef int (*ndn_app_data_cb_t)(ndn_block_t* interest, ndn_block_t* data);

/**
 * @brief  Type for the on_timeout consumer callback.
 */
typedef int (*ndn_app_timeout_cb_t)(ndn_block_t* interest);

/**
 * @brief  Type for the on_interest producer callback.
 */
typedef int (*ndn_app_interest_cb_t)(ndn_block_t* interest);

/**
 * @brief  Type for the error handler.
 */
typedef int (*ndn_app_error_cb_t)(int error);

/**
 * @brief  Type for the consumer callback table entry.
 */
typedef struct _consumer_cb_entry {
    struct _consumer_cb_entry *prev;
    struct _consumer_cb_entry *next;
    ndn_shared_block_t* pi;          /**< expressed interest */
    ndn_app_data_cb_t on_data;       /**< handler for the on_data event */
    ndn_app_timeout_cb_t on_timeout; /**< handler for the on_timeout event */
} _consumer_cb_entry_t;

/**
 * @brief  Type for the producer callback table entry.
 */
typedef struct _producer_cb_entry {
    struct _producer_cb_entry *prev;
    struct _producer_cb_entry *next;
    ndn_shared_block_t* prefix;        /**< registered prefix */
    ndn_app_interest_cb_t on_interest; /**< handler for the on_interest event */
} _producer_cb_entry_t;


/**
 * @brief  Type for the scheduler callback.
 */
typedef int (*ndn_app_sched_cb_t)(void* context);

/**
 * @brief  Type for the scheduler callback table entry.
 */
typedef struct _sched_cb_entry {
    struct _sched_cb_entry *prev;
    struct _sched_cb_entry *next;
    ndn_app_sched_cb_t cb;
    void* context;
    xtimer_t timer;
    msg_t timer_msg;
} _sched_cb_entry_t;


#define NDN_APP_MSG_QUEUE_SIZE  (16)

/**
 * @brief   Type to represent an NDN app handle and its associated context.
 *
 * @details This struct is not lock-protected and should only be accessed from
 *          a single thread.
 */
typedef struct ndn_app {
    kernel_pid_t id;    /**< pid of the app thread */
    msg_t _msg_queue[NDN_APP_MSG_QUEUE_SIZE];  /**< message queue of the app thread */
    _sched_cb_entry_t *_scb_table;      /**< scheduler callback table */
    _consumer_cb_entry_t *_ccb_table;   /**< consumer callback table */
    _producer_cb_entry_t *_pcb_table;   /**< producer callback table */
} ndn_app_t;

/**
 * @brief   Creates a handle for an NDN app and initialize the context.
 *
 * @details This function is reentrant and can be called from multiple threads.
 *
 * @return  Pointer to the newly created @ref ndn_app_t struct, if success.
 * @return  NULL, if cannot allocate memory for the handle.
 */
ndn_app_t* ndn_app_create(void);

/**
 * @brief   Runs the event loop with the app handle.
 *
 * @details This function is reentrant and can be called from multiple threads.
 *          However, the same handle cannot be used twice by this function at
 *          the same time.
 *
 * @param[in]  handle    Handle of the app to run.
 *
 * @return  One of the return codes for the callbacks.
 */
int ndn_app_run(ndn_app_t* handle);

/**
 * @brief   Releases the app handle and all associated memory.
 */
void ndn_app_destroy(ndn_app_t* handle);

/**
 * @brief   Schedules a callback function to be called in some future time.
 *
 * @param[in]  handle    Handler of the app that calls this function.
 * @param[in]  cb        Callback function to be called in the future.
 * @param[in]  context   Parameter supplied to the callback.
 * @param[in]  timeout   Time offset in us, indicating when @p cb is called.
 *
 * @return  0, if success.
 * @return  -1, if @p handle is NULL.
 * @return  -1, if out of memory when allocating memory for the sched entry.
 */
int ndn_app_schedule(ndn_app_t* handle, ndn_app_sched_cb_t cb, void* context,
                     uint32_t timeout);

/**
 * @brief   Sends an interest with specified name, selectors, lifetime and
 *          callbacks.
 *
 * @details This function is reentrant and can be called from multiple threads.
 *
 * @param[in]  handle     Handler of the app that calls this function.
 * @param[in]  name       TLV block of the Interest name.
 * @param[in]  selectors  Selectors of the Interest. Can be NULL if omitted.
 * @param[in]  lifetime   Lifetime of the Interest.
 * @param[in]  on_data    Data handler. Can be NULL.
 * @param[in]  on_timeout Timeout handler. Can be NULL.
 *
 * @return  0, if success.
 * @return  -1, if @p handle or @p name is NULL.
 * @return  -1, if out of memory when allocating memory for pending interest.
 */
int ndn_app_express_interest(ndn_app_t* handle, ndn_block_t* name,
                             void* selectors, uint32_t lifetime,
                             ndn_app_data_cb_t on_data,
                             ndn_app_timeout_cb_t on_timeout);

/**
 * @brief   Sends an interest with specified name, selectors, lifetime, signing key
 *          and callbacks.
 *
 * @details This function is reentrant and can be called from multiple threads.
 *
 * @param[in]  handle     Handler of the app that calls this function.
 * @param[in]  name       TLV block of the Interest name.
 * @param[in]  selectors  Selectors of the Interest. Can be NULL if omitted.
 * @param[in]  lifetime   Lifetime of the Interest.
 * @param[in]  sig_type   Signature type
 * @param[in]  key        Signing key bits
 * @param[in]  key_len    Key bits length
 * @param[in]  on_data    Data handler. Can be NULL.
 * @param[in]  on_timeout Timeout handler. Can be NULL.
 *
 * @return  0, if success.
 * @return  -1, if @p handle or @p name is NULL.
 * @return  -1, if out of memory when allocating memory for pending interest.
 */
int ndn_app_express_signed_interest(ndn_app_t* handle, ndn_block_t* name,
                                    void* selectors, uint32_t lifetime,
                                    uint8_t sig_type, const unsigned char* key,
                                    size_t key_len, 
                                    ndn_app_data_cb_t on_data,
                                    ndn_app_timeout_cb_t on_timeout);

/**
 * @brief   Sends an interest with specified name, selectors, lifetime and
 *          callbacks.
 *
 * @details This function is reentrant and can be called from multiple threads.
 *
 * @param[in]  handle     Handler of the app that calls this function.
 * @param[in]  name       Name of the Interest.
 * @param[in]  selectors  Selectors of the Interest. Can be NULL if omitted.
 * @param[in]  lifetime   Lifetime of the Interest.
 * @param[in]  on_data    Data handler. Can be NULL.
 * @param[in]  on_timeout Timeout handler. Can be NULL.
 *
 * @return  0, if success.
 * @return  -1, if @p handle or @p name is NULL.
 * @return  -1, if out of memory when allocating memory for pending interest.
 */
int ndn_app_express_interest2(ndn_app_t* handle, ndn_name_t* name,
                              void* selectors, uint32_t lifetime,
                              ndn_app_data_cb_t on_data,
                              ndn_app_timeout_cb_t on_timeout);

/**
 * @brief   Registers a prefix with specified callbacks.
 *
 * @details This function is reentrant and can be called from multiple threads.
 *
 * @param[in]  handle     Handler of the app that calls this function.
 * @param[in]  name       Shared block of the name prefix to be registered.
 * @param[in]  on_data    Interest handler. Can be NULL.
 *
 * @return  0, if success.
 * @return  -1, if @p handle or @p name is NULL.
 * @return  -1, if out of memory.
 */
int ndn_app_register_prefix(ndn_app_t* handle, ndn_shared_block_t* name,
                            ndn_app_interest_cb_t on_interest);

/**
 * @brief   Registers a prefix with specified callbacks.
 *
 * @details This function is reentrant and can be called from multiple threads.
 *
 * @param[in]  handle     Handler of the app that calls this function.
 * @param[in]  name       Name prefix to be registered.
 * @param[in]  on_data    Interest handler. Can be NULL.
 *
 * @return  0, if success.
 * @return  -1, if @p handle or @p name is NULL.
 * @return  -1, if out of memory.
 */
int ndn_app_register_prefix2(ndn_app_t* handle, ndn_name_t* name,
                             ndn_app_interest_cb_t on_interest);

/**
 * @brief   Sends a data packet to the NDN thread.
 *
 * @param[in]  handle     Handler of the app that calls this function.
 * @param[in]  sd         Shared TLV block of the data to send.
 *
 * @return  0, if success.
 * @return  -1, if @p handle or @p sd is NULL.
 * @return  -1, if failed to send the packet.
 */
int ndn_app_put_data(ndn_app_t* handle, ndn_shared_block_t* sd);

/**
 * @brief   Sends a TLV block to an app.
 *
 * @param[in]  id       PID of the app to which the block is sent.
 * @param[in]  block    TLV block to send.
 * @param[in]  msg_type Type of the TLV block (Interest or Data).
 */
void ndn_app_send_msg_to_app(kernel_pid_t id, ndn_shared_block_t* block,
                             int msg_type);

// private struct used by add_strategy operation
struct _ndn_app_add_strategy_param {
    ndn_shared_block_t* prefix;
    ndn_forwarding_strategy_t* strategy;
};

/**
 * @brief   Adds @p strategy for @p prefix.
 *
 * @param[in]  prefix  Prefix for which the strategy is set. This function takes
 *                     ownership of this pointer and will pass the ownership to
 *                     the ndn thread.
 * @param[in]  strategy The strategy for @p prefix.
 *
 * @return  0, if success.
 * @return  -1, if failed to set the strategy.
 */
int ndn_app_add_strategy(ndn_shared_block_t* prefix,
			 ndn_forwarding_strategy_t* strategy);

#ifdef __cplusplus
}
#endif

#endif /* NDN_APP_H_ */
/** @} */
