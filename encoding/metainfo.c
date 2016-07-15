/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ndn_encoding
 * @{
 *
 * @file
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */

#include "metainfo.h"

#include <debug.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int ndn_metainfo_total_length(ndn_metainfo_t* meta)
{
    if (meta == NULL) return -1;

    int vl = 0, l;

    if (meta->content_type >= 0) {
        l = ndn_block_integer_length((uint32_t)meta->content_type);
        vl += ndn_block_total_length(NDN_TLV_CONTENT_TYPE, l);
    }
    if (meta->freshness >= 0) {
        l = ndn_block_integer_length((uint32_t)meta->freshness);
        vl += ndn_block_total_length(NDN_TLV_FRESHNESS_PERIOD, l);
    }

    return ndn_block_total_length(NDN_TLV_METAINFO, vl);
}

int ndn_metainfo_wire_encode(ndn_metainfo_t* meta, uint8_t* buf, int len)
{
    if (meta == NULL || buf == NULL) return -1;

    int vl = 0, l;

    if (meta->content_type >= 0) {
        l = ndn_block_integer_length((uint32_t)meta->content_type);
        vl += ndn_block_total_length(NDN_TLV_CONTENT_TYPE, l);
    }
    if (meta->freshness >= 0) {
        l = ndn_block_integer_length((uint32_t)meta->freshness);
        vl += ndn_block_total_length(NDN_TLV_FRESHNESS_PERIOD, l);
    }

    int tl = ndn_block_total_length(NDN_TLV_METAINFO, vl);
    if (tl > len) return -1;

    // write metainfo type
    l = ndn_block_put_var_number(NDN_TLV_METAINFO, buf, len);
    assert(l > 0);
    buf += l;
    len -= l;

    // write metainfo length
    l = ndn_block_put_var_number(vl, buf, len);
    assert(l > 0);
    buf += l;
    len -= l;

    if (meta->content_type >= 0) {
        // write content_type type
        l = ndn_block_put_var_number(NDN_TLV_CONTENT_TYPE, buf, len);
        assert(l > 0);
        buf += l;
        len -= l;

        // write content_type type
        l = ndn_block_integer_length((uint32_t)meta->content_type);
        l = ndn_block_put_integer(l, buf, len);
        assert(l > 0);
        buf += l;
        len -= l;

        // write content_type value
        l = ndn_block_put_integer((uint32_t)meta->content_type, buf, len);
        assert(l > 0);
        buf += l;
        len -= l;
    }

    if (meta->freshness >= 0) {
        // write content_type type
        l = ndn_block_put_var_number(NDN_TLV_FRESHNESS_PERIOD, buf, len);
        assert(l > 0);
        buf += l;
        len -= l;

        // write content_type type
        l = ndn_block_integer_length((uint32_t)meta->freshness);
        l = ndn_block_put_integer(l, buf, len);
        assert(l > 0);
        buf += l;
        len -= l;

        // write content_type value
        l = ndn_block_put_integer((uint32_t)meta->freshness, buf, len);
        assert(l > 0);
        buf += l;
        len -= l;
    }

    return tl;
}

int ndn_metainfo_from_block(const uint8_t* buf, int len, ndn_metainfo_t* meta)
{
    if (buf == NULL || meta == NULL) return -1;

    meta->content_type = meta->freshness = -1;

    uint32_t num;
    int l, tl;

    // check metainfo type
    if (*buf != NDN_TLV_METAINFO) return -1;
    tl = 1;
    buf += 1;
    len -= 1;

    // check metainfo length
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    tl += l;
    buf += l;
    len -= l;
    if ((int)num > len) return -1;

    tl += (int)num;  // record total length
    len = (int)num;
    while (len > 0) {
        // read type
        l = ndn_block_get_var_number(buf, len, &num);
        if (l < 0) return -1;
        if (num == NDN_TLV_CONTENT_TYPE) {
            buf += l;
            len -= l;

            // read length
            l = ndn_block_get_var_number(buf, len, &num);
            if (l < 0) return -1;
            buf += l;
            len -= l;

            // read integer
            l = ndn_block_get_integer(buf, (int)num,
                                      (uint32_t*)&meta->content_type);
            if (l < 0) return -1;
            buf += l;
            len -= l;
        } else if (num == NDN_TLV_FRESHNESS_PERIOD) {
            buf += l;
            len -= l;

            // read length
            l = ndn_block_get_var_number(buf, len, &num);
            if (l < 0) return -1;
            buf += l;
            len -= l;

            // read integer
            l = ndn_block_get_integer(buf, (int)num,
                                      (uint32_t*)&meta->freshness);
            if (l < 0) return -1;
            buf += l;
            len -= l;
        } else {
            // skip unknown type
            buf += l;
            len -= l;

            // read length and skip value
            l = ndn_block_get_var_number(buf, len, &num);
            if (l < 0) return -1;
            buf += l + num;
            len -= l + num;
        }
    }

    if (len != 0) return -1;  // TLV block is invalid
    else return tl;
}

/** @} */
