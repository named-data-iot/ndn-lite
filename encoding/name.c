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

#include "name.h"
#include "ndn-constants.h"

#include <debug.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ndn_name_component_compare(ndn_name_component_t* lhs,
                               ndn_name_component_t* rhs)
{
    if (lhs == NULL || rhs == NULL) return -2;

    if (lhs->buf == NULL && lhs->len != 0) return -2;
    if (rhs->buf == NULL && rhs->len != 0) return -2;

    if (lhs->len < rhs->len) return -1;
    else if (lhs->len > rhs->len) return 1;
    else
    {
        int n = memcmp(lhs->buf, rhs->buf, rhs->len);
        if (n < 0) return -1;
        else if (n > 0) return 1;
        else return 0;
    }
}

int ndn_name_component_wire_encode(ndn_name_component_t* comp, uint8_t* buf,
                                   int len)
{
    if (comp == NULL || buf == NULL || comp->len < 0) return -1;

    if (comp->buf == NULL) {
        // empty component
        if (comp->len != 0) return -1;
        else return 0;
    }

    int tl = ndn_block_total_length(NDN_TLV_NAME_COMPONENT, comp->len);
    if (tl > len) return -1;

    int bytes_written =
        ndn_block_put_var_number(NDN_TLV_NAME_COMPONENT, buf, len);
    bytes_written += ndn_block_put_var_number(comp->len, buf + bytes_written,
                                              len - bytes_written);
    memcpy(buf + bytes_written, comp->buf, comp->len);
    return tl;
}


int ndn_name_compare(ndn_name_t* lhs, ndn_name_t* rhs)
{
    if (lhs == NULL || rhs == NULL) return -2;
    if (lhs->comps == NULL && lhs->size != 0) return -2;
    if (rhs->comps == NULL && rhs->size != 0) return -2;

    for (int i = 0; i < lhs->size && i < rhs->size; ++i)
    {
        int res = ndn_name_component_compare(&lhs->comps[i], &rhs->comps[i]);
        if (res == 0) continue;
        else return res;
    }

    if (lhs->size < rhs->size) return -1;
    else if (lhs->size > rhs->size) return 1;
    else return 0;
}

int ndn_name_get_component(ndn_name_t* name, int pos,
                           ndn_name_component_t* comp)
{
    if (name == NULL || comp == NULL) return -1;

    if (pos >= name->size || pos < -1 * (name->size)) return -1;

    if (pos < 0) pos += name->size;
    *comp = name->comps[pos];
    return 0;
}

/* computes the total length of TLV-encoded components in the name */
static int _ndn_name_length(ndn_name_t* name)
{
    if (name == NULL) return -1;
    if (name->comps == NULL) {
        if (name->size != 0) return -1;
        else return 0;
    }

    int res = 0;
    for (int i = 0; i < name->size; ++i)
    {
        ndn_name_component_t* comp = &name->comps[i];
        if (comp->buf == NULL || comp->len <= 0) return -1;
        res += ndn_block_total_length(NDN_TLV_NAME_COMPONENT, comp->len);
    }
    return res;
}

int ndn_name_total_length(ndn_name_t* name)
{
    int cl = _ndn_name_length(name);
    if (cl < 0) return cl;
    return ndn_block_total_length(NDN_TLV_NAME, cl);
}

int ndn_name_wire_encode(ndn_name_t* name, uint8_t* buf, int len)
{
    if (name == NULL || buf == NULL) return -1;

    int cl = _ndn_name_length(name);
    if (cl < 0) return cl;
    int tl = ndn_block_total_length(NDN_TLV_NAME, cl);
    if (tl > len) return -1;

    int bytes_written = ndn_block_put_var_number(NDN_TLV_NAME, buf, len);
    bytes_written += ndn_block_put_var_number(cl, buf + bytes_written,
                                              len - bytes_written);
    for (int i = 0; i < name->size; ++i)
    {
        bytes_written += ndn_name_component_wire_encode(&name->comps[i],
                                                        buf + bytes_written,
                                                        len - bytes_written);
    }
    return tl;
}

static inline int _check_hex(char c)
{
    if ((c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F') ||
        (c >= '0' && c <= '9'))
        return 1;
    else
        return 0;
}

static inline uint8_t _hex_to_num(char c)
{
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    else {
        switch (c) {
            case 'a':
            case 'A':
                return 10;

            case 'b':
            case 'B':
                return 11;

            case 'c':
            case 'C':
                return 12;

            case 'd':
            case 'D':
                return 13;

            case 'e':
            case 'E':
                return 14;

            case 'f':
            case 'F':
                return 15;

            default:
                break;
        }
        return 0;
    }
}

ndn_shared_block_t* ndn_name_from_uri(const char* uri, int len)
{
    if (uri == NULL || len <= 0) return NULL;

    if (uri[0] != '/') return NULL;  //TODO: support "ndn:" scheme identifier

    // calculate total length & check validity
    int i = 1;
    uint32_t cl = 0;   // length of all TLV-encoded components
    uint32_t cpl = 0;  // length of current component
    while (i < len) {
        if (uri[i] == '/') {
            // found next slash
            if (cpl == 0) return NULL; // empty component

            cl += ndn_block_total_length(NDN_TLV_NAME_COMPONENT, cpl);
            cpl = 0; // clear current component length
            ++i; // move past the next slash
        }
        else if (uri[i] == '%') {
            // check hex-encoded byte
            if (i + 2 >= len) return NULL; // incomplete hex encoding
            if (_check_hex(uri[i+1]) == 0 || _check_hex(uri[i+2]) == 0)
                return NULL; // invalid hex encoding

            ++cpl;
            i += 3;
        }
        else {
            // single byte
            ++cpl;
            ++i;
        }
    }

    if (cpl > 0)  // count last (non-empty) component
        cl += ndn_block_total_length(NDN_TLV_NAME_COMPONENT, cpl);

    // allocate memory
    ndn_block_t name;
    name.len = cl + 1 + ndn_block_var_number_length(cl);
    uint8_t* buf = (uint8_t*)malloc(name.len);
    name.buf = buf;

    // start encoding
    buf[0] = NDN_TLV_NAME;
    int total_len = name.len;
    int ll = ndn_block_put_var_number(cl, buf + 1, total_len - 1);
    buf += ll + 1;
    total_len -= ll + 1;

    // encode each component
    i = 1;
    int j = 1;  // position of the beginning of current component
    cpl = 0;  // length of current component
    while (i <= len) {
        if (i == len && cpl == 0)  // ignore last trailing slash
            break;

        if ((i == len && cpl > 0) || uri[i] == '/') {
            // found next slash
            assert(cpl > 0);

            // encode type
            *buf = NDN_TLV_NAME_COMPONENT;
            // encode length
            ll = ndn_block_put_var_number(cpl, buf + 1, total_len - 1);
            buf += ll + 1;
            total_len -= ll + 1;
            // encode value
            int k = j;
            while (k < i) {
                if (uri[k] == '%') {
                    *buf = (_hex_to_num(uri[k+1]) << 4)
                        + _hex_to_num(uri[k+2]);
                    k += 3;
                }
                else {
                    *buf = (uint8_t)uri[k];
                    k += 1;
                }
                buf += 1;
            }
            assert(k == i);

            cpl = 0; // clear current component length
            ++i; // move past the next slash
            j = i; // mark beginning of next component
        }
        else if (uri[i] == '%') {
            // hex-encoded byte
            assert(i + 2 < len);

            ++cpl;
            i += 3;
        }
        else {
            // single byte
            ++cpl;
            ++i;
        }
    }

    ndn_shared_block_t* shared = ndn_shared_block_create_by_move(&name);
    if (shared == NULL) {
        free((void*)name.buf);
        return NULL;
    }
    return shared;
}

ndn_shared_block_t* ndn_name_append(ndn_block_t* block, const uint8_t* buf,
                                    int len)
{
    if (block == NULL || block->buf == NULL || block->len <= 0 ||
        buf == NULL || len <= 0)
        return NULL;

    uint32_t num;
    int l, cp;

    /* read name type */
    l = ndn_block_get_var_number(block->buf, block->len, &num);
    if (l < 0) return NULL;
    if (num != NDN_TLV_NAME) return NULL;
    cp = l;

    /* read name length */
    l = ndn_block_get_var_number(block->buf + l, block->len - l, &num);
    if (l < 0) return NULL;
    cp += l;

    // total TLV-encoded size of new component
    l = ndn_block_total_length(NDN_TLV_NAME_COMPONENT, len);

    ndn_block_t nb;
    int total_len = ndn_block_total_length(NDN_TLV_NAME, num + (uint32_t)l);
    uint8_t* nbuf = (uint8_t*)malloc(total_len);
    if (nbuf == NULL) return NULL;
    nb.buf = nbuf;
    nb.len = total_len;

    nbuf[0] = NDN_TLV_NAME;
    l = ndn_block_put_var_number(num + (uint32_t)l, nbuf + 1, total_len - 1);
    nbuf += l + 1;
    total_len -= l + 1;

    memcpy(nbuf, block->buf + cp, num);
    nbuf += num;
    total_len -= num;
    *nbuf = NDN_TLV_NAME_COMPONENT;
    l = ndn_block_put_var_number(len, nbuf + 1, total_len - 1);
    memcpy(nbuf + l + 1, buf, len);
    assert(total_len == l + 1 + len);

    ndn_shared_block_t* shared = ndn_shared_block_create_by_move(&nb);
    if (shared == NULL) {
        free((void*)nb.buf);
        return NULL;
    }
    return shared;
}

int ndn_name_get_size_from_block(ndn_block_t* block)
{
    if (block == NULL || block->buf == NULL || block->len <= 0) return -1;

    const uint8_t* buf = block->buf;
    int len = block->len;
    uint32_t num;
    int l;

    /* read name type */
    if (*buf != NDN_TLV_NAME) return -1;
    buf += 1;
    len -= 1;

    /* read name length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    if ((int)num > len) // entire name must reside in a continuous memory block
        return -1;

    int res = 0;
    len = (int)num;

    while (len > 0) {
        /* read name component type */
        if (*buf != NDN_TLV_NAME_COMPONENT) return -1;
        buf += 1;
        len -= 1;

        ++res;

        /* read name component length and skip value */
        num = 0;
        l = ndn_block_get_var_number(buf, len, &num);
        if (l < 0) return -1;
        buf += l + (int)num;
        len -= l + (int)num;
    }

    assert(len == 0);

    return res;
}

int ndn_name_get_component_from_block(ndn_block_t* block, int pos,
                                      ndn_name_component_t* comp)
{
    if (comp == NULL || pos < 0) return -1;

    if (block == NULL || block->buf == NULL || block->len <= 0) return -1;

    const uint8_t* buf = block->buf;
    int len = block->len;
    uint32_t num;
    int l;

    /* read name type */
    if (*buf != NDN_TLV_NAME) return -1;
    buf += 1;
    len -= 1;

    /* read name length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    if ((int)num > len) // entire name must reside in a continuous memory block
        return -1;

    int cnt = 0;
    len = (int)num;

    while (len > 0) {
        /* read name component type */
        if (*buf != NDN_TLV_NAME_COMPONENT) return -1;
        buf += 1;
        len -= 1;

        /* read name component length and skip value */
        num = 0;
        l = ndn_block_get_var_number(buf, len, &num);
        if (l < 0) return -1;
        buf += l;
        len -= l;

        if (cnt == pos) {
            /* found the component we're looking for */
            comp->buf = buf;
            comp->len = num;
            return 0;
        }

        buf += num;
        len -= num;
        ++cnt;
    }

    assert(len == 0);

    return -1;
}

int ndn_name_compare_block(ndn_block_t* lhs, ndn_block_t* rhs)
{
    if (lhs == NULL || lhs->buf == NULL || lhs->len <= 0) return 3;
    if (rhs == NULL || rhs->buf == NULL || rhs->len <= 0) return -3;

    const uint8_t* lbuf = lhs->buf;
    const uint8_t* rbuf = rhs->buf;
    int llen = lhs->len;
    int rlen = rhs->len;
    uint32_t num;
    int l;

    /* check left name type */
    if (*lbuf != NDN_TLV_NAME) return 3;
    lbuf += 1;
    llen -= 1;

    /* check right name type */
    if (*rbuf != NDN_TLV_NAME) return -3;
    rbuf += 1;
    rlen -= 1;

    /* read left name length */
    l = ndn_block_get_var_number(lbuf, llen, &num);
    if (l < 0) return 3;
    lbuf += l;
    llen -= l;

    if ((int)num > llen)  // name is incomplete
        return 3;
    llen = (int)num;

    /* read right name length */
    l = ndn_block_get_var_number(rbuf, rlen, &num);
    if (l < 0) return -3;
    rbuf += l;
    rlen -= l;

    if ((int)num > rlen)  // name is incomplete
        return -3;
    rlen = (int)num;

    int r = memcmp(lbuf, rbuf, llen < rlen ? llen : rlen);
    if (r < 0) return -1;
    else if (r > 0) return 1;
    else {
        if (llen < rlen) return -2;
        else if (llen > rlen) return 2;
        else return 0;
    }
}

static inline int _need_escape(uint8_t c)
{
    if ((c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') ||
        c == '+' || c == '.' || c == '_' || c == '-')
        return 0;
    else
        return 1;
}

void ndn_name_print(ndn_block_t* block)
{
    const uint8_t* buf = block->buf;
    int len = block->len;
    uint32_t num;
    int l;

    /* read name type */
    if (*buf != NDN_TLV_NAME) return;
    buf += 1;
    len -= 1;

    /* read and ignore name length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return;
    buf += l;
    len -= l;

    while (len > 0) {
        /* read name component type */
        if (*buf != NDN_TLV_NAME_COMPONENT) return;
        buf += 1;
        len -= 1;

        /* read name component length */
        l = ndn_block_get_var_number(buf, len, &num);
        if (l < 0) return;
        buf += l;
        len -= l;

        putchar('/');
        for (int i = 0; i < (int)num; ++i) {
            if (_need_escape(buf[i]) == 0)
                printf("%c", buf[i]);
            else
                printf("%%%02X", buf[i]);
        }

        buf += (int)num;
        len -= (int)num;
    }
}

/** @} */
