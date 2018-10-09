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
 * @brief   NDN Interest interface.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_INTEREST_H_
#define NDN_INTEREST_H_

#include "name.h"

#include <net/gnrc/pktbuf.h>

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Creates a shared TLV block that contains the encoded Interest
 *          packet.
 *
 * @param[in]  name       TLV block of the Interest name.
 * @param[in]  selectors  Selectors of the Interest. Can be NULL if omitted.
 * @param[in]  lifetime   Lifetime of the Interest.
 *
 * @return  Pointer to the shared block, if success.
 * @return  -1, if @p name is NULL or invalid.
 * @return  -1, if out of memory.
 */
ndn_shared_block_t* ndn_interest_create(ndn_block_t* name, void* selectors,
                                        uint32_t lifetime);

/**
 * @brief   Creates a shared TLV block that contains the encoded Interest
 *          packet.
 *
 * @param[in]  name       Name of the Interest.
 * @param[in]  selectors  Selectors of the Interest. Can be NULL if omitted.
 * @param[in]  lifetime   Lifetime of the Interest.
 *
 * @return  Pointer to the shared block, if success.
 * @return  -1, if @p name is NULL or invalid.
 * @return  -1, if out of memory.
 */
ndn_shared_block_t* ndn_interest_create2(ndn_name_t* name, void* selectors,
                                         uint32_t lifetime);

/**
 * @brief  Retrieves the TLV-encoded name from an Interest TLV block.
 *
 * @param[in]  block      TLV block containing the Interest packet.
 * @param[out] name       Place to store the TLV block of the name.
 *
 * @return  0, if success.
 * @return  -1, if @p block or @p name is NULL.
 * @return  -1, if @p block is invalid or incomplete.
 */
int ndn_interest_get_name(ndn_block_t* block, ndn_block_t* name);

/**
 * @brief  Retrieves the nonce value from an Interest TLV block.
 *
 * @param[in]  block      TLV block containing the Interest packet.
 * @param[out] nonce      Place to store the nonce value.
 *
 * @return  0, if success.
 * @return  -1, if @p block or @p nonce is NULL.
 * @return  -1, if @p block is invalid or incomplete.
 */
int ndn_interest_get_nonce(ndn_block_t* block, uint32_t* nonce);

/**
 * @brief  Retrieves the lifetime value from an Interest TLV block.
 *
 * @param[in]  block      TLV block containing the Interest packet.
 * @param[out] life       Place to store the lifetime value.
 *
 * @return  0, if success.
 * @return  -1, if @p block or @p life is NULL.
 * @return  -1, if @p block is invalid or incomplete.
 */
int ndn_interest_get_lifetime(ndn_block_t* block, uint32_t* life);

/**
 * @brief   Creates a shared TLV block that contains the encoded signed 
 *          Interest packet.
 *
 * @param[in]  name       TLV block of the Interest name.
 * @param[in]  selectors  Selectors of the Interest. Can be NULL if omitted.
 * @param[in]  lifetime   Lifetime of the Interest.
 * @param[in]  sig_type   Signature Algorithm (e.g., ECDSA, HMAC)
 * @param[in]  key_name   Key who sign this interest, can be NULL
 * @param[in]  key        Key bits
 * @param[in]  key_len    Key bits length
 * @param[in]  index      Indicating the index of using ECDSA curve (if using ECDSA to sign)
 * 
 * @return  Pointer to the shared block, if success.
 * @return  -1, if @p name is NULL or invalid.
 * @return  -1, if out of memory.
 * @return  NULL, if incorrect sig_type or key_len.
 */
ndn_shared_block_t* ndn_signed_interest_create_with_index(ndn_block_t* name, void* selectors,
                                                uint8_t sig_type, uint32_t lifetime,
                                                ndn_block_t* key_name,
                                                const unsigned char* key,
                                                size_t key_len, int index);

/**
 * @brief    Verifies the signature of the TLV encoded Interest packet
 * @details  If the data packet is signed by DigestSha256 algorithm, the key
 *           is ignored.
 *
 * @return  0, if verification succeeds.
 * @return  -1, if @p block is NULL.
 * @return  -1, if @p key is NULL or @p key_len <= 0
 * @return  -1, if verification fails.
 */
int ndn_interest_verify_signature_with_index(ndn_block_t* block,
                              const unsigned char* key,
                              uint32_t algorithm,
                              size_t key_len, int index);

#ifdef __cplusplus
}
#endif

#endif /* NDN_INTEREST_H_ */
/** @} */
