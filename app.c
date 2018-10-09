/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ndn
 * @{
 *
 * @file
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */

#include "app.h"
#include "encoding/name.h"
#include "encoding/interest.h"
#include "encoding/data.h"
#include "msg-type.h"
#include "ndn.h"

#include <debug.h>
#include <msg.h>
#include <thread.h>
#include <utlist.h>
#include <net/gnrc/netapi.h>
#include <net/gnrc/netreg.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

ndn_app_t* ndn_app_create(void)
{
    if (ndn_pid == KERNEL_PID_UNDEF) {
        DEBUG("ndn_app: ndn thread not initialized (pid=%"
              PRIkernel_pid ")\n", thread_getpid());
        return NULL;
    }

    ndn_app_t *handle = (ndn_app_t*)malloc(sizeof(ndn_app_t));
    if (handle == NULL) {
        DEBUG("ndn_app: cannot alloacte memory for app handle (pid=%"
              PRIkernel_pid ")\n", thread_getpid());
        return NULL;
    }

    handle->id = thread_getpid();  // set to caller pid
    handle->_scb_table = NULL;
    handle->_ccb_table = NULL;
    handle->_pcb_table = NULL;

    // add face id to face table
    msg_t add_face, reply;
    add_face.type = NDN_APP_MSG_TYPE_ADD_FACE;
    add_face.content.value = (uint32_t)handle->id;
    reply.content.value = 1;
    msg_send_receive(&add_face, &reply, ndn_pid);
    if (reply.content.value != 0) {
        DEBUG("ndn_app: cannot add app face (pid=%"
              PRIkernel_pid ")\n", handle->id);
        free(handle);
        return NULL;
    }

    // init msg queue to receive message
    msg_init_queue(handle->_msg_queue, NDN_APP_MSG_QUEUE_SIZE);

    return handle;
}

static int _notify_consumer_timeout(ndn_app_t* handle, ndn_block_t* pi)
{
    ndn_block_t pn;
    if (ndn_interest_get_name(pi, &pn) != 0) {
        DEBUG("ndn_app: cannot parse name from pending interest (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return NDN_APP_ERROR;
    }

    _consumer_cb_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(handle->_ccb_table, entry, tmp) {
        ndn_block_t n;
        int r = ndn_interest_get_name(&entry->pi->block, &n);
        assert(r == 0);

        if (0 != memcmp(pn.buf, n.buf, pn.len < n.len ? pn.len : n.len)) {
            // not the same interest name
            //TODO: check selectors
            continue;
        }

        // raise timeout callback
        r = NDN_APP_CONTINUE;
        if (entry->on_timeout != NULL) {
            DEBUG("ndn_app: call consumer timeout cb (pid=%"
                  PRIkernel_pid ")\n", handle->id);
            r = entry->on_timeout(&entry->pi->block);
        }

        DL_DELETE(handle->_ccb_table, entry);
        ndn_shared_block_release(entry->pi);
        free(entry);

        // stop the app now if the callback returns error or stop
        if (r != NDN_APP_CONTINUE) return r;
        // otherwise continue
    }

    return NDN_APP_CONTINUE;
}

static int _notify_producer_interest(ndn_app_t* handle, ndn_block_t* interest)
{
    ndn_block_t name;
    if (ndn_interest_get_name(interest, &name) != 0) {
        DEBUG("ndn_app: cannot parse name from received interest (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return NDN_APP_ERROR;
    }

    _producer_cb_entry_t *entry;
    DL_FOREACH(handle->_pcb_table, entry) {
        if (-2 != ndn_name_compare_block(&entry->prefix->block, &name)) {
            continue;
        }

        // raise interest callback
        int r = NDN_APP_CONTINUE;
        if (entry->on_interest != NULL) {
            DEBUG("ndn_app: call producer interest cb (pid=%"
                  PRIkernel_pid ")\n", handle->id);
            r = entry->on_interest(interest);
        }

        // stop the app now if the callback returns error or stop
        if (r != NDN_APP_CONTINUE) return r;
        // otherwise continue
    }

    return NDN_APP_CONTINUE;
}

static int _notify_consumer_data(ndn_app_t* handle, ndn_block_t* data)
{
    ndn_block_t name;
    if (ndn_data_get_name(data, &name) != 0) {
        DEBUG("ndn_app: cannot parse name from received data (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return NDN_APP_ERROR;
    }

    _consumer_cb_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(handle->_ccb_table, entry, tmp) {
        ndn_block_t n;
        int r = ndn_interest_get_name(&entry->pi->block, &n);
        assert(r == 0);

        // prefix matching
        r = ndn_name_compare_block(&n, &name);
        if (r != -2 && r != 0) {
            continue;
        }

        // raise data callback
        r = NDN_APP_CONTINUE;
        if (entry->on_data != NULL) {
            DEBUG("ndn_app: call consumer data cb (pid=%"
                  PRIkernel_pid ")\n", handle->id);
            r = entry->on_data(&entry->pi->block, data);
        }

        DL_DELETE(handle->_ccb_table, entry);
        ndn_shared_block_release(entry->pi);
        free(entry);

        // stop the app now if the callback returns error or stop
        if (r != NDN_APP_CONTINUE) return r;
        // otherwise continue
    }

    return NDN_APP_CONTINUE;
}

static int _sched_call_cb(ndn_app_t* handle, msg_t* msg)
{
    int r = NDN_APP_ERROR;

    _sched_cb_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(handle->_scb_table, entry, tmp) {
        if (&entry->timer_msg == msg) {
            DEBUG("ndn_app: call scheduled callback (pid=%"
                  PRIkernel_pid ")\n", handle->id);
            DL_DELETE(handle->_scb_table, entry);
            r = entry->cb(entry->context);
            free(entry);
            break;
        }
    }

    return r;
}

int ndn_app_run(ndn_app_t* handle)
{
    if (handle == NULL) return NDN_APP_ERROR;

    int ret = NDN_APP_CONTINUE;
    ndn_shared_block_t* ptr;
    msg_t msg, reply;
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
    reply.content.value = (uint32_t)(-ENOTSUP);

    while (1) {
        msg_receive(&msg);

        switch (msg.type) {
            case NDN_APP_MSG_TYPE_TERMINATE:
                DEBUG("ndn_app: TERMINATE msg received from thread %"
                      PRIkernel_pid " (pid=%" PRIkernel_pid ")\n",
                      msg.sender_pid, handle->id);
                return NDN_APP_STOP;

            case MSG_XTIMER:
                DEBUG("ndn_app: XTIMER msg received from thread %"
                      PRIkernel_pid " (pid=%" PRIkernel_pid ")\n",
                      msg.sender_pid, handle->id);

                ret = _sched_call_cb(handle, (msg_t*)msg.content.ptr);

                break;

            case NDN_APP_MSG_TYPE_TIMEOUT:
                DEBUG("ndn_app: TIMEOUT msg received from thread %"
                      PRIkernel_pid " (pid=%" PRIkernel_pid ")\n",
                      msg.sender_pid, handle->id);
                ptr = (ndn_shared_block_t*)msg.content.ptr;

                ret = _notify_consumer_timeout(handle, &ptr->block);

                ndn_shared_block_release(ptr);

                break;

            case NDN_APP_MSG_TYPE_INTEREST:
                DEBUG("ndn_app: INTEREST msg received from thread %"
                      PRIkernel_pid " (pid=%" PRIkernel_pid ")\n",
                      msg.sender_pid, handle->id);
                ptr = (ndn_shared_block_t*)msg.content.ptr;

                ret = _notify_producer_interest(handle, &ptr->block);

                ndn_shared_block_release(ptr);

                break;

            case NDN_APP_MSG_TYPE_DATA:
                DEBUG("ndn_app: DATA msg received from thread %"
                      PRIkernel_pid " (pid=%" PRIkernel_pid ")\n",
                      msg.sender_pid, handle->id);
                ptr = (ndn_shared_block_t*)msg.content.ptr;

                ret = _notify_consumer_data(handle, &ptr->block);

                ndn_shared_block_release(ptr);

                break;

            case GNRC_NETAPI_MSG_TYPE_GET:
            case GNRC_NETAPI_MSG_TYPE_SET:
                msg_reply(&msg, &reply);
                break;
            default:
                DEBUG("ndn_app: unknown msg type %u (pid=%" PRIkernel_pid ")\n",
                      msg.type, handle->id);
                break;
        }

        if (ret != NDN_APP_CONTINUE) {
            DEBUG("ndn_app: stop app because callback returned"
                  " %s (pid=%" PRIkernel_pid ")\n",
                  ret == NDN_APP_STOP ? "STOP" : "ERROR",
                  handle->id);
            return ret;
        }
    }

    return ret;
}

static inline void _release_sched_cb_table(ndn_app_t* handle)
{
    _sched_cb_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(handle->_scb_table, entry, tmp) {
        DEBUG("ndn_app: remove scheduler cb entry (pid=%"
              PRIkernel_pid ")\n", handle->id);
        DL_DELETE(handle->_scb_table, entry);
        xtimer_remove(&entry->timer);
        free(entry);
    }
}

static inline void _release_consumer_cb_table(ndn_app_t* handle)
{
    _consumer_cb_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(handle->_ccb_table, entry, tmp) {
        DEBUG("ndn_app: remove consumer cb entry (pid=%"
              PRIkernel_pid ")\n", handle->id);
        DL_DELETE(handle->_ccb_table, entry);
        ndn_shared_block_release(entry->pi);
        free(entry);
    }
}

static inline void _release_producer_cb_table(ndn_app_t* handle)
{
    _producer_cb_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(handle->_pcb_table, entry, tmp) {
        DEBUG("ndn_app: remove producer cb entry (pid=%"
              PRIkernel_pid ")\n", handle->id);
        DL_DELETE(handle->_pcb_table, entry);
        ndn_shared_block_release(entry->prefix);
        free(entry);
    }
}

void ndn_app_destroy(ndn_app_t* handle)
{
    _release_sched_cb_table(handle);
    _release_consumer_cb_table(handle);
    _release_producer_cb_table(handle);

    // remove face id to face table
    msg_t add_face, reply;
    add_face.type = NDN_APP_MSG_TYPE_REMOVE_FACE;
    add_face.content.value = (uint32_t)handle->id;
    reply.content.value = 1;
    msg_send_receive(&add_face, &reply, ndn_pid);
    if (reply.content.value != 0) {
        DEBUG("ndn_app: error removing app face (pid=%"
              PRIkernel_pid ")\n", handle->id);
        // ignore the error anyway...
    }

    //TODO: clear msg queue
    free(handle);
}

static _sched_cb_entry_t*
_add_sched_cb_entry(ndn_app_t* handle, ndn_app_sched_cb_t cb, void* context)
{
    _sched_cb_entry_t* entry =
        (_sched_cb_entry_t*)malloc(sizeof(_sched_cb_entry_t));
    if (entry == NULL) {
        DEBUG("ndn_app: cannot allocate memory for sched cb entry (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return NULL;
    }

    entry->cb = cb;
    entry->context = context;

    DL_PREPEND(handle->_scb_table, entry);
    DEBUG("ndn_app: add sched cb entry (pid=%"
          PRIkernel_pid ")\n", handle->id);
    return entry;
}

int ndn_app_schedule(ndn_app_t* handle, ndn_app_sched_cb_t cb, void* context,
                     uint32_t timeout)
{
    if (handle == NULL) return -1;

    _sched_cb_entry_t *entry =
        _add_sched_cb_entry(handle, cb, context);
    if (entry == NULL) return -1;

    // initialize the timer
    entry->timer.target = entry->timer.long_target = 0;

    // initialize the msg struct
    entry->timer_msg.type = MSG_XTIMER;
    entry->timer_msg.content.ptr = (char*)(&entry->timer_msg);

    // set a timer to send a message to the app thread
    xtimer_set_msg(&entry->timer, timeout, &entry->timer_msg, handle->id);

    return 0;
}

static _consumer_cb_entry_t*
_add_consumer_cb_entry(ndn_app_t* handle, ndn_shared_block_t* si,
                       ndn_app_data_cb_t on_data,
                       ndn_app_timeout_cb_t on_timeout)
{
    _consumer_cb_entry_t *entry =
        (_consumer_cb_entry_t*)malloc(sizeof(_consumer_cb_entry_t));
    if (entry == NULL) {
        DEBUG("ndn_app: cannot allocate memory for consumer cb entry (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return NULL;
    }

    entry->on_data = on_data;
    entry->on_timeout = on_timeout;
    entry->pi = ndn_shared_block_copy(si);

    DL_PREPEND(handle->_ccb_table, entry);
    DEBUG("ndn_app: add consumer cb entry (pid=%"
          PRIkernel_pid ")\n", handle->id);
    return entry;
}

int ndn_app_express_interest(ndn_app_t* handle, ndn_block_t* name,
                             void* selectors, uint32_t lifetime,
                             ndn_app_data_cb_t on_data,
                             ndn_app_timeout_cb_t on_timeout)
{
    if (handle == NULL) return -1;

    // create encoded TLV block
    ndn_shared_block_t* si = ndn_interest_create(name, selectors, lifetime);
    if (si == NULL) {
        DEBUG("ndn_app: cannot create interest block (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return -1;
    }

    // add entry to consumer callback table
    _consumer_cb_entry_t *entry
        = _add_consumer_cb_entry(handle, si, on_data, on_timeout);
    if (entry == NULL) {
        ndn_shared_block_release(si);
        return -1;
    }

    // send interest to NDN thread
    msg_t send;
    send.type = NDN_APP_MSG_TYPE_INTEREST;
    send.content.ptr = (void*)si;
    if (msg_try_send(&send, ndn_pid) < 1) {
        DEBUG("ndn_app: cannot send interest to NDN thread (pid=%"
              PRIkernel_pid ")\n", handle->id);
        ndn_shared_block_release(si);
        // remove consumer cb entry
        DL_DELETE(handle->_ccb_table, entry);
        ndn_shared_block_release(entry->pi);
        free(entry);
        return -1;
    }
    // NDN thread will own the shared block ptr

    return 0;
}

int ndn_app_express_signed_interest(ndn_app_t* handle, ndn_block_t* name,
                                    void* selectors, uint32_t lifetime,
                                    uint8_t sig_type, const unsigned char* key,
                                    size_t key_len, 
                                    ndn_app_data_cb_t on_data,
                                    ndn_app_timeout_cb_t on_timeout)
{
    if (handle == NULL) return -1;

    // create encoded TLV block
    ndn_shared_block_t* si = ndn_signed_interest_create_with_index(name, selectors, sig_type, lifetime, 
                                                                   NULL, key, key_len, 0);
    if (si == NULL) {
        DEBUG("ndn_app: cannot create interest block (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return -1;
    }

    // add entry to consumer callback table
    _consumer_cb_entry_t *entry
        = _add_consumer_cb_entry(handle, si, on_data, on_timeout);
    if (entry == NULL) {
        ndn_shared_block_release(si);
        return -1;
    }

    // send interest to NDN thread
    msg_t send;
    send.type = NDN_APP_MSG_TYPE_INTEREST;
    send.content.ptr = (void*)si;
    if (msg_try_send(&send, ndn_pid) < 1) {
        DEBUG("ndn_app: cannot send interest to NDN thread (pid=%"
              PRIkernel_pid ")\n", handle->id);
        ndn_shared_block_release(si);
        // remove consumer cb entry
        DL_DELETE(handle->_ccb_table, entry);
        ndn_shared_block_release(entry->pi);
        free(entry);
        return -1;
    }
    // NDN thread will own the shared block ptr

    return 0;
}

int ndn_app_express_interest2(ndn_app_t* handle, ndn_name_t* name,
                              void* selectors, uint32_t lifetime,
                              ndn_app_data_cb_t on_data,
                              ndn_app_timeout_cb_t on_timeout)
{
    if (handle == NULL) return -1;

    // create encoded TLV block
    ndn_shared_block_t* si = ndn_interest_create2(name, selectors, lifetime);
    if (si == NULL) {
        DEBUG("ndn_app: cannot create interest block (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return -1;
    }

    // add entry to consumer callback table
    _consumer_cb_entry_t *entry
        = _add_consumer_cb_entry(handle, si, on_data, on_timeout);
    if (entry == NULL) {
        ndn_shared_block_release(si);
        return -1;
    }

    // send interest to NDN thread
    msg_t send;
    send.type = NDN_APP_MSG_TYPE_INTEREST;
    send.content.ptr = (void*)si;
    if (msg_try_send(&send, ndn_pid) < 1) {
        DEBUG("ndn_app: cannot send interest to NDN thread (pid=%"
              PRIkernel_pid ")\n", handle->id);
        ndn_shared_block_release(si);
        // remove consumer cb entry
        DL_DELETE(handle->_ccb_table, entry);
        ndn_shared_block_release(entry->pi);
        free(entry);
        return -1;
    }
    // NDN thread will own the shared block ptr

    return 0;
}

static _producer_cb_entry_t*
_add_producer_cb_entry(ndn_app_t* handle, ndn_shared_block_t* n,
                       ndn_app_interest_cb_t on_interest)
{
    _producer_cb_entry_t *entry =
        (_producer_cb_entry_t*)malloc(sizeof(_producer_cb_entry_t));
    if (entry == NULL) {
        DEBUG("ndn_app: cannot allocate memory for producer cb entry (pid=%"
              PRIkernel_pid ")\n", handle->id);
        return NULL;
    }

    entry->prefix = ndn_shared_block_copy(n);
    entry->on_interest = on_interest;

    DL_PREPEND(handle->_pcb_table, entry);
    DEBUG("ndn_app: add producer cb entry (pid=%"
          PRIkernel_pid ")\n", handle->id);
    return entry;
}

int ndn_app_register_prefix(ndn_app_t* handle, ndn_shared_block_t* name,
                            ndn_app_interest_cb_t on_interest)
{
    if (handle == NULL) {
        ndn_shared_block_release(name);
        return -1;
    }

    _producer_cb_entry_t* entry =
        _add_producer_cb_entry(handle, name, on_interest);
    if (entry == NULL) {
        DEBUG("ndn_app: failed to add producer cb entry (pid=%"
              PRIkernel_pid ")", handle->id);
        ndn_shared_block_release(name);
        return -1;
    }

    // notify ndn thread to add fib entry
    msg_t add_fib, reply;
    add_fib.type = NDN_APP_MSG_TYPE_ADD_FIB;

    // once received, this pointer will be released by the ndn thread
    add_fib.content.ptr = (void*)name;

    reply.content.value = 1;
    msg_send_receive(&add_fib, &reply, ndn_pid);
    if (reply.content.value != 0) {
        DEBUG("ndn_app: cannot add fib entry (pid=%"
              PRIkernel_pid ")\n", handle->id);
        DL_DELETE(handle->_pcb_table, entry);
        ndn_shared_block_release(entry->prefix);
        free(entry);
        return -1;
    }

    return 0;
}

int ndn_app_register_prefix2(ndn_app_t* handle, ndn_name_t* name,
                             ndn_app_interest_cb_t on_interest)
{
    if (handle == NULL) return -1;

    ndn_block_t n;
    n.len = ndn_name_total_length(name);
    if (n.len <= 0) return -1;
    n.buf = (const uint8_t*)malloc(n.len);
    if (ndn_name_wire_encode(name, (uint8_t*)n.buf, n.len) <= 0) return -1;

    ndn_shared_block_t* sn = ndn_shared_block_create_by_move(&n);
    if (sn == NULL) {
        DEBUG("ndn_app: cannot create shared block for prefix (pid=%"
              PRIkernel_pid ")", handle->id);
        free((void*)n.buf);
        return -1;
    }

    return ndn_app_register_prefix(handle, sn, on_interest);
}

int ndn_app_put_data(ndn_app_t* handle, ndn_shared_block_t* sd)
{
    if (handle == NULL || sd == NULL) return -1;

    // send data to NDN thread
    msg_t send;
    send.type = NDN_APP_MSG_TYPE_DATA;
    send.content.ptr = (void*)sd;
    if (msg_try_send(&send, ndn_pid) < 1) {
        DEBUG("ndn_app: cannot send data to NDN thread (pid=%"
              PRIkernel_pid ")\n", handle->id);
        ndn_shared_block_release(sd);
        return -1;
    }
    // NDN thread will own the shared block ptr

    return 0;
}

int ndn_app_add_strategy(ndn_shared_block_t* prefix,
			 ndn_forwarding_strategy_t* strategy)
{
    struct _ndn_app_add_strategy_param param;
    param.prefix = prefix;  // receiver of this message takes the ownership
    param.strategy = strategy;
    msg_t op, reply;
    op.type = NDN_APP_MSG_TYPE_ADD_STRATEGY;
    op.content.ptr = (void*)(&param);

    reply.content.value = 1;
    msg_send_receive(&op, &reply, ndn_pid);
    if (reply.content.value != 0) {
        DEBUG("ndn_app: cannot add forwarding strategy\n");
        return -1;
    }
    return 0;
}

void ndn_app_send_msg_to_app(kernel_pid_t id, ndn_shared_block_t* block,
                             int msg_type)
{
    msg_t m;
    m.type = msg_type;
    m.content.ptr = (void*)block;
    if (msg_try_send(&m, id) < 1) {
        DEBUG("ndn: cannot send msg to pid %"
              PRIkernel_pid "\n", id);
        // release the shared ptr here
        ndn_shared_block_release(block);
    }
    DEBUG("ndn: msg sent to pid %" PRIkernel_pid "\n", id);
}

/** @} */
