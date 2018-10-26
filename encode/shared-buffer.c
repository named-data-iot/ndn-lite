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

#include "shared-buffer.h"

#include <debug.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

ndn_shared_buffer_t* ndn_shared_buffer_create(ndn_buffer_t* buffer)
{
    if (buffer == NULL || buffer->buf == NULL || buffer->len <= 0)
        return NULL;

    ndn_shared_buffer_t* shared =
        (ndn_shared_buffer_t*)malloc(sizeof(ndn_shared_buffer_t));
    if (shared == NULL) {
        DEBUG("ndn: cannot allocate memory for shared buffer\n");
        return NULL;
    }

    memset(shared, 0, sizeof(ndn_shared_buffer_t));

    uint8_t* nbuf = (uint8_t*)malloc(buffer->len);
    if (nbuf == NULL) {
        DEBUG("ndn: cannot allocate memory for shared buffer content\n");
        free(shared);
        return NULL;
    }
    memcpy(nbuf, buffer->buf, buffer->len);
    shared->buffer.buf = nbuf;
    shared->buffer.len = buffer->len;
    atomic_init(&shared->ref, 1);
    return shared;
}

ndn_shared_buffer_t* ndn_shared_buffer_create_by_move(ndn_buffer_t* buffer)
{
    if (buffer == NULL || buffer->buf == NULL || buffer->len <= 0)
        return NULL;

    ndn_shared_buffer_t* shared =
        (ndn_shared_buffer_t*)malloc(sizeof(ndn_shared_buffer_t));
    if (shared == NULL) {
        DEBUG("ndn: cannot allocate memory for shared buffer\n");
        return NULL;
    }

    memset(shared, 0, sizeof(ndn_shared_buffer_t));

    // "Move" memory into the shared buffer
    shared->buffer.buf = buffer->buf;
    shared->buffer.len = buffer->len;
    buffer->buf = NULL;
    buffer->len = 0;
    atomic_init(&shared->ref, 1);
    return shared;
}

void ndn_shared_buffer_release(ndn_shared_buffer_t* shared)
{
    assert(shared != NULL);
    int ref =
      atomic_fetch_sub_explicit(&shared->ref, 1, memory_order_acq_rel) - 1;
    if (ref == 0) {
        /* no one is using this buffer; free the memory. */
        DEBUG("ndn: free shared buffer memory\n");
        free((void*)shared->buffer.buf);
        free(shared);
    }
    return;
}

ndn_shared_buffer_t* ndn_shared_buffer_copy(ndn_shared_buffer_t* shared)
{
    assert(shared != NULL);
    atomic_fetch_add_explicit(&shared->ref, 1, memory_order_acq_rel);
    return shared;
}


/** @} */
