/*
 * Copyright (C) 2017 Wentao Shang
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

#include "forwarding-strategy.h"
#include "fib.h"
#include "pit.h"
#include "app.h"
#include "msg-type.h"
#include "netif.h"
#include "encoding/name.h"
#include "encoding/interest.h"

#define ENABLE_DEBUG 1
#include <debug.h>

#define STRATEGY_TABLE_MAX_SIZE 8

typedef struct _strategy_table_entry {
    ndn_shared_block_t* prefix;
    int plen;
    ndn_forwarding_strategy_t strategy;
} _strategy_table_entry_t;

static _strategy_table_entry_t _strategy_table[STRATEGY_TABLE_MAX_SIZE];
static int _strategy_table_size;

ndn_forwarding_strategy_t* ndn_forwarding_strategy_lookup(ndn_block_t* name)
{
    if (name == NULL) return NULL;

    int max_plen = -1;
    ndn_forwarding_strategy_t *max_strategy = NULL;
    for (int i = 0; i < _strategy_table_size; ++i) {
	_strategy_table_entry_t* entry = &_strategy_table[i];
	int r =
            ndn_name_compare_block(&entry->prefix->block, name);
        if (r == 0 || r == -2) {
            // prefix in this entry matches the name
            if (entry->plen > max_plen) {
                max_plen = entry->plen;
                max_strategy = &entry->strategy;
            }
        }
    }
    return max_strategy;
}

int ndn_forwarding_strategy_add(ndn_shared_block_t* prefix,
				ndn_forwarding_strategy_t* strategy)
{
    if (prefix == NULL) return -1;
    if (strategy == NULL) return -1;
    if (strategy->after_receive_interest == NULL) return -1;
    if (_strategy_table_size == STRATEGY_TABLE_MAX_SIZE) {
	DEBUG("ndn: strategy table is full (%d entries)\n",
	      _strategy_table_size);
	ndn_shared_block_release(prefix);
	return -1;
    }

    // check for existing entry with same prefix
    for (int i = 0; i < _strategy_table_size; ++i) {
	_strategy_table_entry_t* entry = &_strategy_table[i];
	int r =
            ndn_name_compare_block(&entry->prefix->block, &prefix->block);
        if (r == 0) {
            // found entry with the same prefix
	    DEBUG("ndn: overwrite forwarding strategy for existing entry\n");
	    entry->strategy = *strategy;
	    // we're done
	    return 0;
        }	
    }

    // add new entry
    _strategy_table_entry_t* entry = &_strategy_table[_strategy_table_size++];
    entry->prefix = prefix;  // move semantics
    entry->plen = ndn_name_get_size_from_block(&prefix->block);
    entry->strategy = *strategy;
    return 0;
}

void ndn_forwarding_strategy_action_send_interest(ndn_shared_block_t* si,
						  kernel_pid_t face_id,
						  int face_type)
{
    switch (face_type) {
        case NDN_FACE_NETDEV:
            DEBUG("ndn: send to netdev face %" PRIkernel_pid "\n", face_id);
            ndn_netif_send(face_id, &si->block);
            ndn_shared_block_release(si);
            break;

        case NDN_FACE_APP:
            DEBUG("ndn: send to app face %" PRIkernel_pid "\n", face_id);
            ndn_app_send_msg_to_app(face_id, si, NDN_APP_MSG_TYPE_INTEREST);
            break;

        default:
            ndn_shared_block_release(si);
            break;
    }
    return;
}

static void default_strategy_after_receive_interest(ndn_shared_block_t* si,
						    kernel_pid_t incoming_face,
						    ndn_pit_entry_t* pit_entry)
{
    DEBUG("ndn: in default strategy trigger: after_receive_interest\n");

    ndn_block_t name;
    ndn_interest_get_name(&si->block, &name);

    (void)pit_entry;

    // check fib
    ndn_fib_entry_t* fib_entry = ndn_fib_lookup(&name);
    if (fib_entry == NULL) {
        DEBUG("ndn: no route for interest name, drop packet\n");
        ndn_shared_block_release(si);
        return;
    }

    if (fib_entry->face_list_size == 0 || fib_entry->face_list == NULL) {
	DEBUG("ndn: no outgoing face in the fib entry\n");
	ndn_shared_block_release(si);
        return;
    }

    int index;
    for (index = 0; index < fib_entry->face_list_size; ++index) {
        // find the first face that is different from the incoming face
        if (fib_entry->face_list[index].id != incoming_face)
            break;
    }
    if (index == fib_entry->face_list_size) {
        DEBUG("ndn: no face available for forwarding\n");
        ndn_shared_block_release(si);
        return;
    }
    ndn_forwarding_strategy_action_send_interest
	(si, fib_entry->face_list[index].id, fib_entry->face_list[index].type);
    return;
}

ndn_forwarding_strategy_t default_strategy = {
    .after_receive_interest = default_strategy_after_receive_interest,
    .before_satisfy_interest = NULL,
    .before_expire_pending_interest = NULL
};

static void
multicast_strategy_after_receive_interest(ndn_shared_block_t* si,
					  kernel_pid_t incoming_face,
					  ndn_pit_entry_t* pit_entry)
{
    DEBUG("ndn: in multicast strategy trigger: after_receive_interest\n");

    ndn_block_t name;
    ndn_interest_get_name(&si->block, &name);

    (void)pit_entry;

    // check fib
    ndn_fib_entry_t* fib_entry = ndn_fib_lookup(&name);
    if (fib_entry == NULL) {
        DEBUG("ndn: no route for interest name, drop packet\n");
        ndn_shared_block_release(si);
        return;
    }

    if (fib_entry->face_list_size == 0 || fib_entry->face_list == NULL) {
	DEBUG("ndn: no outgoing face in the fib entry\n");
	ndn_shared_block_release(si);
        return;
    }

    // forward to all outgoing faces that are not the same as incoming face
    for (int index = 0; index < fib_entry->face_list_size; ++index) {
        if (fib_entry->face_list[index].id != incoming_face) {
	    ndn_forwarding_strategy_action_send_interest
		(ndn_shared_block_copy(si), fib_entry->face_list[index].id,
		 fib_entry->face_list[index].type);
	}
    }
    ndn_shared_block_release(si);
    return;
}

ndn_forwarding_strategy_t multicast_strategy = {
    .after_receive_interest = multicast_strategy_after_receive_interest,
    .before_satisfy_interest = NULL,
    .before_expire_pending_interest = NULL
};

void ndn_forwarding_strategy_init(void)
{
    _strategy_table_size = 0;
    memset(&_strategy_table, 0, sizeof _strategy_table);
    // add default strategy for default prefix "/"
    uint8_t buf[] = { NDN_TLV_NAME, 0 };
    ndn_block_t empty = { buf, sizeof(buf) }; // URI = "/"
    ndn_forwarding_strategy_add(ndn_shared_block_create(&empty),
				&default_strategy);
}

/** @} */
