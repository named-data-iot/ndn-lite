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

#include "pit.h"
#include "encoding/interest.h"
#include "encoding/data.h"
#include "msg-type.h"
#include "face-table.h"
#include "forwarding-strategy.h"
#include "netif.h"
#include "ndn.h"
#include "app.h"

#define ENABLE_DEBUG 1
#include <debug.h>
#include <utlist.h>

#include <assert.h>
#include <stdlib.h>

static ndn_pit_entry_t *_pit;

static ndn_pit_entry_t* _pit_entry_add_face(ndn_pit_entry_t* entry,
                                            kernel_pid_t id, int type)
{
    if (entry->face_list == NULL) {
        entry->face_list =
            (_face_list_entry_t*)malloc(sizeof(_face_list_entry_t));
        if (entry->face_list == NULL) {
            DEBUG("ndn: fail to allocate memory for face list\n");
            return NULL;
        }
        entry->face_list_size = 1;
        entry->face_list[0].id = id;
        entry->face_list[0].type = type;
        return entry;
    } else {
        // check for existing face entry
        for (int i = 0; i < entry->face_list_size; ++i) {
            if (entry->face_list[i].id == id) {
                DEBUG("ndn: same interest from same face exists\n");
                return entry;
            }
        }

        // need to add a new entry to the face list
        _face_list_entry_t *list =
            (_face_list_entry_t*)realloc(
                entry->face_list,
                (entry->face_list_size + 1) * sizeof(_face_list_entry_t));
        if (list == NULL) {
            DEBUG("ndn: fail to reallocate memory for face list (size=%d)\n",
                  entry->face_list_size);
            return NULL;
        }
        entry->face_list = list;
        entry->face_list[entry->face_list_size].id = id;
        entry->face_list[entry->face_list_size].type = type;
        ++entry->face_list_size;
        return entry;
    }
}

int ndn_pit_add(kernel_pid_t face_id, int face_type, ndn_shared_block_t* si,
		struct ndn_forwarding_strategy* strategy,
		ndn_pit_entry_t** pit_entry)
{
    if (si == NULL) return -1;
    if (strategy == NULL) return -1;

    ndn_block_t name;
    if (0 != ndn_interest_get_name(&si->block, &name)) {
        DEBUG("ndn: cannot get interest name for pit insertion\n");
        return -1;
    }

    uint32_t lifetime;
    if (0 != ndn_interest_get_lifetime(&si->block, &lifetime)) {
        DEBUG("ndn: cannot get lifetime from Interest block\n");
        return -1;
    }

    if (lifetime > 0x400000) {
        DEBUG("ndn: interest lifetime in us exceeds 32-bit\n");
        return -1;
    }

    /* convert lifetime to us */
    lifetime *= US_PER_MS;

    // check for interests with the same name and selectors
    ndn_pit_entry_t *entry;
    DL_FOREACH(_pit, entry) {
        // get and compare name
        ndn_block_t pn;
        int r = ndn_interest_get_name(&entry->shared_pi->block, &pn);
        assert(r == 0);
        (void) r;

        if (0 == memcmp(pn.buf, name.buf,
                        (pn.len < name.len ? pn.len : name.len))) {
            // Found pit entry with the same name
            if (NULL ==  _pit_entry_add_face(entry, face_id, face_type))
                return -1;
            else {
                DEBUG("ndn: add to existing pit entry (face=%"
                      PRIkernel_pid ")\n", face_id);
                /* reset timer */
                xtimer_set_msg(&entry->timer, lifetime, &entry->timer_msg,
                               ndn_pid);
		// overwrite forwarding strategy
		entry->forwarding_strategy = strategy;
		if (pit_entry != NULL)
		    *pit_entry = entry;
                return 1;
            }
        }
        //TODO: also check selectors
    }

    // no pending entry found, allocate new entry
    entry = (ndn_pit_entry_t*)malloc(sizeof(ndn_pit_entry_t));
    if (entry == NULL) {
        DEBUG("ndn: cannot allocate pit entry\n");
        return -1;
    }

    entry->shared_pi = ndn_shared_block_copy(si);
    entry->prev = entry->next = NULL;
    entry->face_list = NULL;
    entry->face_list_size = 0;

    if (NULL == _pit_entry_add_face(entry, face_id, face_type)) {
        ndn_shared_block_release(entry->shared_pi);
        free(entry);
        return -1;
    }

    DL_PREPEND(_pit, entry);
    if (pit_entry != NULL)
	*pit_entry = entry;

    /* initialize the timer */
    entry->timer.target = entry->timer.long_target = 0;

    /* initialize the msg struct */
    entry->timer_msg.type = NDN_PIT_MSG_TYPE_TIMEOUT;
    entry->timer_msg.content.ptr = (char*)(&entry->timer_msg);

    /* set a timer to send a message to ndn thread */
    xtimer_set_msg(&entry->timer, lifetime, &entry->timer_msg, ndn_pid);

    // set forwarding strategy
    entry->forwarding_strategy = strategy;

    DEBUG("ndn: add new pit entry (face=%" PRIkernel_pid ")\n", face_id);
    return 0;
}

void ndn_pit_release(ndn_pit_entry_t *entry)
{
    assert(_pit != NULL);
    DL_DELETE(_pit, entry);
    xtimer_remove(&entry->timer);
    ndn_shared_block_release(entry->shared_pi);
    free(entry->face_list);
    free(entry);
}

void ndn_pit_timeout(msg_t *msg)
{
    assert(_pit != NULL);

    ndn_pit_entry_t *elem, *tmp;
    DL_FOREACH_SAFE(_pit, elem, tmp) {
        if (&elem->timer_msg == msg) {
            DEBUG("ndn: remove pit entry due to timeout (face_list_size=%d)\n",
                  elem->face_list_size);

	    // invoke forwarding strategy trigger if available
	    if (elem->forwarding_strategy->before_expire_pending_interest) {
		DEBUG("ndn: invoke forwarding strategy trigger: before_expire_"
		      "pending_interest\n");
		elem->forwarding_strategy->before_expire_pending_interest(elem);
	    } else {
		DEBUG("ndn: forwarding strategy does not have trigger: before_ "
		      "expire_pending_interest\n");
	    }

            // notify app face, if any
            msg_t timeout;
            timeout.type = NDN_APP_MSG_TYPE_TIMEOUT;
            for (int i = 0; i < elem->face_list_size; ++i) {
                if (elem->face_list[i].type == NDN_FACE_APP) {
                    DEBUG("ndn: try to send timeout message to pid %"
                          PRIkernel_pid "\n", elem->face_list[i].id);
                    timeout.content.ptr =
                        (void*)ndn_shared_block_copy(elem->shared_pi);
                    if (msg_try_send(&timeout, elem->face_list[i].id) < 1) {
                        DEBUG("ndn: cannot send timeout message to pid %"
                              PRIkernel_pid "\n", elem->face_list[i].id);
                        // release the shared ptr here
                        ndn_shared_block_release(
                            (ndn_shared_block_t*)timeout.content.ptr);
                    }
                    // message delivered to app thread, which is responsible
                    // for releasing the shared ptr
                }
            }
            ndn_pit_release(elem);
        }
    }
}

int ndn_pit_match_data(ndn_shared_block_t* sd, kernel_pid_t iface)
{
    assert(sd != NULL);

    if (_pit == NULL)  // no PIT entry exists
        return -1;

    ndn_block_t name;
    if (0 != ndn_data_get_name(&sd->block, &name)) {
        DEBUG("ndn: cannot get data name for pit matching\n");
        return -1;
    }

    int found = -1;
    ndn_pit_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(_pit, entry, tmp) {
        ndn_block_t pn;
        int r = ndn_interest_get_name(&entry->shared_pi->block, &pn);
        assert(r == 0);

        r = ndn_name_compare_block(&pn, &name);
        if (r == -2 || r == 0) {
            // either pn is a prefix of name, or they are the same
            found = 0;
	    DEBUG("ndn: found matching pit entry for data\n");

            DL_DELETE(_pit, entry);
            xtimer_remove(&entry->timer);

	    // invoke forwarding strategy trigger if available
	    if (entry->forwarding_strategy->before_satisfy_interest) {
		DEBUG("ndn: invoke forwarding strategy trigger: before_satisfy_"
		      "interest\n");
		entry->forwarding_strategy->before_satisfy_interest
		    (&sd->block, iface, entry);
	    } else {
		DEBUG("ndn: forwarding strategy does not have trigger: before_"
		      "satisfy_interest\n");
	    }

            for (int i = 0; i < entry->face_list_size; ++i) {
                kernel_pid_t id = entry->face_list[i].id;
                if (id == iface)
                    continue;  // do not send back to incoming face

                switch (entry->face_list[i].type) {
                    case NDN_FACE_NETDEV:
                        DEBUG("ndn: send data to netdev face %"
                              PRIkernel_pid "\n", id);
                        ndn_netif_send(id, &sd->block);
                        break;

                    case NDN_FACE_APP:
                        DEBUG("ndn: send data to app face %"
                              PRIkernel_pid "\n", id);
                        ndn_shared_block_t* ssd = ndn_shared_block_copy(sd);
                        ndn_app_send_msg_to_app(id, ssd, NDN_APP_MSG_TYPE_DATA);
                        break;

                    default:
                        break;
                }
            }

            ndn_shared_block_release(entry->shared_pi);
            free(entry->face_list);
            free(entry);
        }
    }
    return found;
}

void ndn_pit_init(void)
{
    _pit = NULL;
}


/** @} */
