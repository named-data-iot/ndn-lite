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

#include "ndn.h"
#include "face-table.h"
#include "netif.h"
#include "l2.h"
#include "pit.h"
#include "fib.h"
#include "cs.h"
#include "encoding/ndn-constants.h"
#include "encoding/name.h"
#include "encoding/interest.h"
#include "msg-type.h"

#include <debug.h>
#include <net/gnrc/netapi.h>
#include <net/gnrc/netif.h>
#include <net/gnrc/netreg.h>
#include <thread.h>
#include <timex.h>
#include <xtimer.h>

#define GNRC_NDN_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT)
#define GNRC_NDN_PRIO              (THREAD_PRIORITY_MAIN - 3)
#define GNRC_NDN_MSG_QUEUE_SIZE    (8U)

#if ENABLE_DEBUG
static char _stack[GNRC_NDN_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_NDN_STACK_SIZE];
#endif

kernel_pid_t ndn_pid = KERNEL_PID_UNDEF;

static void _send_msg_to_app(kernel_pid_t id, ndn_shared_block_t* block,
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

static void _process_interest(kernel_pid_t face_id, int face_type,
                              ndn_shared_block_t* si)
{
    assert(si != NULL);

    ndn_shared_block_t* sd = ndn_cs_match(&si->block);
    if (sd != NULL) {
        ndn_shared_block_release(si);

        // return data to incoming face
        switch (face_type) {
            case NDN_FACE_NETDEV:
                DEBUG("ndn: send cached data to netdev face %"
                      PRIkernel_pid "\n", face_id);
                ndn_netif_send(face_id, &sd->block);
                ndn_shared_block_release(sd);
                break;

            case NDN_FACE_APP:
                DEBUG("ndn: send cached data to app face %"
                      PRIkernel_pid "\n", face_id);
                _send_msg_to_app(face_id, sd, NDN_APP_MSG_TYPE_DATA);
                break;

            default:
                ndn_shared_block_release(sd);
                break;
        }

        return;
    }

    /* add to pit table */
    if (ndn_pit_add(face_id, face_type, si) != 0) {
        ndn_shared_block_release(si);
        return;
    }

    /* check fib */
    ndn_block_t name;
    if (ndn_interest_get_name(&si->block, &name) < 0) {
        DEBUG("ndn: cannot get name from interest block\n");
        ndn_shared_block_release(si);
        return;
    }

    ndn_fib_entry_t* fib_entry = ndn_fib_lookup(&name);
    if (fib_entry == NULL) {
        DEBUG("ndn: no route for interest name, drop packet\n");
        ndn_shared_block_release(si);
        return;
    }

    /* send to the first available interface */
    //TODO: differet forwarding strategies
    assert(fib_entry->face_list_size > 0);
    assert(fib_entry->face_list != NULL);

    int index;
    for (index = 0; index < fib_entry->face_list_size; ++index) {
        // find the first face that is different from the incoming face
        if (fib_entry->face_list[index].id != face_id)
            break;
    }
    if (index == fib_entry->face_list_size) {
        DEBUG("ndn: no face available for forwarding\n");
        ndn_shared_block_release(si);
        return;
    }

    kernel_pid_t iface = fib_entry->face_list[index].id;
    switch (fib_entry->face_list[index].type) {
        case NDN_FACE_NETDEV:
            DEBUG("ndn: send to netdev face %" PRIkernel_pid "\n", iface);
            ndn_netif_send(iface, &si->block);
            ndn_shared_block_release(si);
            break;

        case NDN_FACE_APP:
            DEBUG("ndn: send to app face %" PRIkernel_pid "\n", iface);
            _send_msg_to_app(iface, si, NDN_APP_MSG_TYPE_INTEREST);
            break;

        default:
            ndn_shared_block_release(si);
            break;
    }

    return;
}

static void _process_data(kernel_pid_t face_id, int face_type,
                          ndn_shared_block_t* sd)
{
    assert(sd != NULL);

    (void)face_type;

    // match data against pit
    if (ndn_pit_match_data(sd, face_id) == 0) {
        // found match in pit
        // try to add data to CS
        ndn_cs_add(sd);
    } // otherwise drop unsolicited data

    ndn_shared_block_release(sd);
}

static void _process_packet(kernel_pid_t face_id, int face_type,
                            gnrc_pktsnip_t *pkt)
{
    assert(pkt != NULL);
    assert(pkt->type == GNRC_NETTYPE_NDN);

    ndn_shared_block_t* sb = NULL;

    uint8_t* buf = (uint8_t*)pkt->data;
    /* check if the packet starts with l2 fragmentation header */
    if (buf[0] & NDN_L2_FRAG_HB_MASK) {
        uint16_t frag_id = (buf[1] << 8) + buf[2];
        DEBUG("ndn: l2 fragment received (MF=%x, SEQ=%u, ID=%02x, "
              "packet size = %d, iface=%" PRIkernel_pid ")\n",
              (buf[0] & NDN_L2_FRAG_MF_MASK) >> 5,
              buf[0] & NDN_L2_FRAG_SEQ_MASK,
              frag_id, pkt->size, face_id);
        sb = ndn_l2_frag_receive(face_id, pkt, frag_id);
    }
    else {
        ndn_block_t block;
        if (ndn_block_from_packet(pkt, &block) != 0) {
            DEBUG("ndn: cannot get block from packet\n");
            gnrc_pktbuf_release(pkt);
            return;
        }
        sb = ndn_shared_block_create(&block);
        gnrc_pktbuf_release(pkt);
    }

    if (sb != NULL) {
        // Read type
        uint32_t num;
        if (ndn_block_get_var_number(
                sb->block.buf, sb->block.len, &num) < 0) {
            DEBUG("ndn: cannot read NDN packet type from shared block\n");
            ndn_shared_block_release(sb);
            return;
        }

        switch (num) {
            case NDN_TLV_INTEREST:
                _process_interest(face_id, face_type, sb);
                break;

            case NDN_TLV_DATA:
                _process_data(face_id, face_type, sb);
                break;

            default:
                DEBUG("ndn: unknown reassembled packet type\n");
                ndn_shared_block_release(sb);
                break;
        }
    }
    return;
}

/* Main event loop for NDN */
static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[GNRC_NDN_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t me_reg;

    (void)args;
    msg_init_queue(msg_q, GNRC_NDN_MSG_QUEUE_SIZE);

    me_reg.demux_ctx = GNRC_NETREG_DEMUX_CTX_ALL;
    me_reg.target.pid = thread_getpid();

    /* register interest in all NDN packets */
    gnrc_netreg_register(GNRC_NETTYPE_NDN, &me_reg);

    /* preinitialize ACK to GET/SET commands*/
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    /* start event loop */
    while (1) {
        msg_receive(&msg);

        switch (msg.type) {
            case NDN_PIT_MSG_TYPE_TIMEOUT:
                DEBUG("ndn: PIT TIMEOUT message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                ndn_pit_timeout((msg_t*)msg.content.ptr);
                break;

            case NDN_L2_FRAG_MSG_TYPE_TIMEOUT:
                DEBUG("ndn: L2_FRAG TIMEOUT message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                ndn_l2_frag_timeout((msg_t*)msg.content.ptr);
                break;

            case NDN_APP_MSG_TYPE_ADD_FACE:
                DEBUG("ndn: ADD_FACE message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                if (ndn_face_table_add(
                        (kernel_pid_t)msg.content.value, NDN_FACE_APP) != 0) {
                    DEBUG("ndn: failed to add face id %d\n",
                          (int)msg.content.value);
                    reply.content.value = 1;
                } else {
                    reply.content.value = 0;  // indicate success
                }
                msg_reply(&msg, &reply);
                break;

            case NDN_APP_MSG_TYPE_REMOVE_FACE:
                DEBUG("ndn: REMOVE_FACE message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                if (ndn_face_table_remove(
                        (kernel_pid_t)msg.content.value) != 0) {
                    DEBUG("ndn: failed to remove face id %d\n",
                          (int)msg.content.value);
                    reply.content.value = 1;
                } else {
                    reply.content.value = 0;  // indicate success
                }
                msg_reply(&msg, &reply);
                break;

            case NDN_APP_MSG_TYPE_ADD_FIB:
                DEBUG("ndn: ADD_FIB message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                if (ndn_fib_add((ndn_shared_block_t*)msg.content.ptr,
                                msg.sender_pid,
                                NDN_FACE_APP) != 0) {
                    DEBUG("ndn: failed to add fib entry\n");
                    ndn_shared_block_release(
                        (ndn_shared_block_t*)msg.content.ptr);
                    reply.content.value = 1;
                } else {
                    reply.content.value = 0;  // indicate success
                }
                msg_reply(&msg, &reply);
                break;

            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("ndn: RCV message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                _process_packet(msg.sender_pid, NDN_FACE_NETDEV,
                                (gnrc_pktsnip_t *)msg.content.ptr);
                break;

            case NDN_APP_MSG_TYPE_INTEREST:
                DEBUG("ndn: INTEREST message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                _process_interest(msg.sender_pid, NDN_FACE_APP,
                                  (ndn_shared_block_t*)msg.content.ptr);
                break;

            case NDN_APP_MSG_TYPE_DATA:
                DEBUG("ndn: DATA message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                _process_data(msg.sender_pid, NDN_FACE_APP,
                                  (ndn_shared_block_t*)msg.content.ptr);
                break;

            case GNRC_NETAPI_MSG_TYPE_GET:
            case GNRC_NETAPI_MSG_TYPE_SET:
                reply.content.value = -ENOTSUP;
                msg_reply(&msg, &reply);
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUG("ndn: SND message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
            default:
                break;
        }
    }

    return NULL;
}


kernel_pid_t ndn_init(void)
{
    ndn_face_table_init();
    ndn_fib_init();
    ndn_netif_auto_add();

    ndn_pit_init();
    ndn_cs_init();

    /* check if thread is already running */
    if (ndn_pid == KERNEL_PID_UNDEF) {
        /* start UDP thread */
        ndn_pid = thread_create(
            _stack, sizeof(_stack), GNRC_NDN_PRIO,
            THREAD_CREATE_STACKTEST, _event_loop, NULL, "ndn");
    }
    return ndn_pid;
}

/** @} */
