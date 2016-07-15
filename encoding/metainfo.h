/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ndn_encoding    NDN packet encoding
 * @ingroup     net_ndn
 * @brief       NDN TLV packet encoding and decoding.
 * @{
 *
 * @file
 * @brief   NDN Metainfo interface.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_METAINFO_H_
#define NDN_METAINFO_H_

#include "name.h"

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Type to represent NDN metainfo.
 */
typedef struct ndn_metainfo {
    int32_t content_type;    /**< content type; -1 if not present */
    int32_t freshness;       /**< freshness period; -1 if not present */
} ndn_metainfo_t;

/**
 * @brief   Computes the total encoded length of the metainfo.
 *
 * @param[in]  meta    Metainfo structure.
 *
 * @return  Total encoded length of @p meta, if success.
 * @return  -1, if @p meta is NULL.
 */
int ndn_metainfo_total_length(ndn_metainfo_t* meta);

/**
 * @brief   Encodes the metainfo into TLV format in the caller-supplied buffer.
 *
 * @param[in]  meta    Metainfo to be encoded.
 * @param[out] buf     Buffer to store the encoded TLV block.
 * @param[in]  len     Size of the buffer pointed by @p buf.
 *
 * @return  Number of bytes written into the buffer, if success.
 * @return  -1, if buffer is not big enough.
 * @return  -1, if @p meta is NULL or @p len <= 0.
 */
int ndn_metainfo_wire_encode(ndn_metainfo_t* meta, uint8_t* buf, int len);

/**
 * @brief   Reads the metainfo from a TLV encoded block.
 *
 * @param[in]  buf     Buffer that stores the encoded TLV block.
 * @param[in]  len     Size of the buffer pointed by @p buf.
 * @param[out] meta    Struct to store the parsed metainfo.
 *
 * @return  Number of bytes read, if success.
 * @return  -1, if the metainfo block is invalid or incomplete.
 * @return  -1, if @p meta or @p buf is NULL or @p len <= 0.
 */
int ndn_metainfo_from_block(const uint8_t* buf, int len, ndn_metainfo_t* meta);

#ifdef __cplusplus
}
#endif

#endif /* NDN_METAINFO_H_ */
/** @} */
