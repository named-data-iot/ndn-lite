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

#include <utlist.h>
#include <debug.h>

#include <stdlib.h>

static ndn_face_entry_t *_face_table;

int ndn_face_table_size(void)
{
    ndn_face_entry_t *entry;
    int size;
    DL_COUNT(_face_table, entry, size);
    return size;
}

ndn_face_entry_t* ndn_face_table_find(kernel_pid_t id)
{
    ndn_face_entry_t* entry;
    DL_SEARCH_SCALAR(_face_table, entry, id, id);
    return entry;
}

int ndn_face_table_add(kernel_pid_t id, int type)
{
    ndn_face_entry_t *entry = ndn_face_table_find(id);
    if (entry != NULL) {
        DEBUG("ndn: face entry (id=%" PRIkernel_pid ") already exists\n", id);
        return -1;
    }

    entry = (ndn_face_entry_t*)malloc(sizeof(ndn_face_entry_t));
    if (entry == NULL) {
        DEBUG("ndn: cannot allocate face entry (id=%" PRIkernel_pid ")\n", id);
        return -1;
    }

    entry->prev = entry->next = NULL;
    entry->id = id;
    entry->type = type;
    DL_PREPEND(_face_table, entry);
    DEBUG("ndn: add face entry (id=%" PRIkernel_pid ", type=%d)\n", id, type);
    return 0;
}

int ndn_face_table_remove(kernel_pid_t id)
{
    ndn_face_entry_t *entry, *tmp;
    DL_FOREACH_SAFE(_face_table, entry, tmp) {
        if (entry->id == id) {
            DL_DELETE(_face_table, entry);
            free(entry);
            DEBUG("ndn: remove face entry (id=%" PRIkernel_pid ", type=%d)\n",
                  entry->id, entry->type);
            return 0;
        }
    }
    return -1;
}

void ndn_face_table_init(void)
{
    _face_table = NULL;
}

/** @} */
