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

#include "face-table.h"

#include <debug.h>

#include <stdlib.h>
#include <string.h>

static ndn_face_entry_t _face_table[NDN_FACE_ENTRIES_NUMOF];

int ndn_face_table_size(void)
{
    int size = 0;
    for (int i = 0; i < NDN_FACE_ENTRIES_NUMOF; ++i) {
        if (_face_table[i].id != KERNEL_PID_UNDEF) {
            size++;
        }
    }
    return size;
}

ndn_face_entry_t* ndn_face_table_find(kernel_pid_t id)
{
    for (int i = 0; i < NDN_FACE_ENTRIES_NUMOF; ++i) {
        if (_face_table[i].id == id) {
            return &_face_table[i];
        }
    }
    return NULL;
}

int ndn_face_table_add(kernel_pid_t id, int type)
{
    ndn_face_entry_t *entry = NULL;

    for (int i = 0; i < NDN_FACE_ENTRIES_NUMOF; ++i) {
        if (_face_table[i].id == id) {
            DEBUG("ndn: face entry (id=%" PRIkernel_pid ") already exists\n", id);
            return -1;
        }

        if ((!entry) && (_face_table[i].id == KERNEL_PID_UNDEF)) {
            entry = &_face_table[i];
        }
    }

    if (!entry) {
        DEBUG("ndn: cannot allocate face entry (id=%" PRIkernel_pid ")\n", id);
        return -1;
    }

    entry->prev = entry->next = NULL;
    entry->id = id;
    entry->type = type;
    DEBUG("ndn: add face entry (id=%" PRIkernel_pid ", type=%d)\n", id, type);
    return 0;
}

int ndn_face_table_remove(kernel_pid_t id)
{
    ndn_face_entry_t *entry = ndn_face_table_find(id);
    if (entry) {
        DEBUG("ndn: remove face entry (id=%" PRIkernel_pid ", type=%d)\n",
              entry->id, entry->type);
        memset(entry, 0, sizeof(*entry));
        entry->id = KERNEL_PID_UNDEF;
        return 0;
    }

    return -1;
}

void ndn_face_table_init(void)
{
    for (int i = 0; i < NDN_FACE_ENTRIES_NUMOF; ++i) {
        _face_table[i].id = KERNEL_PID_UNDEF;
    }
}

/** @} */
