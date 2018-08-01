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
 * @brief   NDN Data interface.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_DATA_H_
#define NDN_DATA_H_

#include "name.h"
#include "metainfo.h"

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Creates a shared TLV block that contains the encoded Data packet.
 *
 * @param[in]  name          TLV block of the data name.
 * @param[in]  metainfo      Metainfo of the data.
 * @param[in]  content       Content of the data.
 * @param[in]  sig_type      Signature type.
 * @param[in]  key_name      Name of the key to be encoded in KeyLocator.
 * @param[in]  key           Pointer to the HMAC key. If NULL, the data packet
 *                           will be signed with DIGEST_SHA256 signature.
 * @param[in]  key_len       Length of the HMAC key. Ignored if @p key is NULL.
 *
 * @return  Pointer to the shared TLV block, if success.
 * @return  NULL, if out of memory when allocating the block.
 * @return  NULL, if @p name, @p metainfo or @p content is NULL or invalid.
 * @return  NULL, if @p key and @p key_len does not match @p sig_type.
 */
ndn_shared_block_t* ndn_data_create(ndn_block_t* name,
                                    ndn_metainfo_t* metainfo,
                                    ndn_block_t* content,
                                    uint8_t sig_type,
                                    ndn_block_t* key_name,
                                    const unsigned char* key,
                                    size_t key_len);

/**
 * @brief   Creates a shared TLV block that contains the encoded Data packet.
 *
 * @param[in]  name          Name of the data.
 * @param[in]  metainfo      Metainfo of the data.
 * @param[in]  content       Content of the data.
 * @param[in]  sig_type      Signature type.
 * @param[in]  key_name      Name of the key to be encoded in KeyLocator.
 * @param[in]  key           Pointer to the HMAC key. If NULL, the data packet
 *                           will be signed with DIGEST_SHA256 signature.
 * @param[in]  key_len       Length of the HMAC key. Ignored if @p key is NULL.
 *
 * @return  Pointer to the shared TLV block, if success.
 * @return  NULL, if out of memory when allocating the block.
 * @return  NULL, if @p name, @p metainfo or @p content is NULL or invalid.
 * @return  NULL, if @p key and @p key_len does not match @p sig_type.
 */
ndn_shared_block_t* ndn_data_create2(ndn_name_t* name,
                                     ndn_metainfo_t* metainfo,
                                     ndn_block_t* content,
                                     uint8_t sig_type,
                                     ndn_name_t* key_name,
                                     const unsigned char* key,
                                     size_t key_len);

#define NDN_DATA_CCM_KEY_LEN      16
#define NDN_DATA_CCM_NONCE_LEN    8
#define NDN_DATA_CCM_AUTH_TAG_LEN 12
#define NDN_DATA_CCM_LENGTH_ENCODING 2

/**
 * @brief   Creates a shared TLV block that contains the encoded Data packet
 *          encrypted and signed by AES-CCM authenticated encryption algorithm.
 *
 * @param[in]  name          TLV block of the data name.
 * @param[in]  content       Content of the data.
 * @param[in]  key           Pointer to the AES-CCM key.
 * @param[in]  key_len       Length of the AES-CCM key.
 *
 * @return  Pointer to the shared TLV block, if success.
 * @return  NULL, if out of memory when allocating the block.
 * @return  NULL, if @p name or @p content is NULL or invalid.
 * @return  NULL, if @p key is NULL.
 * @return  NULL, if @p key_len is not NDN_DATA_CCM_KEY_LEN.
 * @return  NULL, if cipher API returns failure.
 */
ndn_shared_block_t* ndn_data_encrypt_with_ccm(ndn_block_t* name,
					      ndn_block_t* content,
					      const uint8_t* key,
					      uint8_t key_len);

/**
 * @brief  Retrieves the TLV-encoded name from a Data TLV block.
 *
 * @param[in]  block      TLV block containing the Data packet.
 * @param[out] name       Place to store the TLV block of the name.
 *
 * @return  0, if success.
 * @return  -1, if @p block or @p name is NULL.
 * @return  -1, if @p block is invalid or incomplete.
 */
int ndn_data_get_name(ndn_block_t* block, ndn_block_t* name);

/**
 * @brief  Retrieves the metainfo from a Data TLV block.
 *
 * @param[in]  block      TLV block containing the Data packet.
 * @param[out] meta       Place to store the metainfo struct.
 *
 * @return  0, if success.
 * @return  -1, if @p block or @p meta is NULL.
 * @return  -1, if @p block is invalid or incomplete.
 */
int ndn_data_get_metainfo(ndn_block_t* block, ndn_metainfo_t* meta);

/**
 * @brief  Retrieves the TLV-encoded content from a Data TLV block.
 *
 * @param[in]  block      TLV block containing the Data packet.
 * @param[out] content    Place to store the TLV block of the content.
 *
 * @return  0, if success.
 * @return  -1, if @p block or @p content is NULL.
 * @return  -1, if @p block is invalid or incomplete.
 */
int ndn_data_get_content(ndn_block_t* block, ndn_block_t* content);

/**
 * @brief  Retrieves the TLV-encoded key locator name from a Data TLV block.
 *
 * @param[in]  block      TLV block containing the Data packet.
 * @param[out] key_name   Place to store the TLV block of the key name.
 *
 * @return  0, if success.
 * @return  -1, if @p block or @p content is NULL.
 * @return  -1, if @p block is invalid or incomplete.
 * @return  -2, if key locator is not present in the packet.
 * @return  -3, if key locator does not contain a key name.
 */
int ndn_data_get_key_locator(ndn_block_t* block, ndn_block_t* key_name);

/**
 * @brief    Verifies the signature of the data packet with caller-supplied
 *           HMAC key.
 * @details  If the data packet is signed by DigestSha256 algorithm, the key
 *           is ignored.
 *
 * @return  0, if verification succeeds.
 * @return  -1, if @p block is NULL.
 * @return  -1, if @p key is NULL or @p key_len <= 0, and the data is signed
 *          by HMAC-SHA256 algorithm.
 * @return  -1, if verification fails.
 */
int ndn_data_verify_signature(ndn_block_t* block, const unsigned char* key,
                              size_t key_len);

/**
 * @brief    Decrypts and authenticates the data packet with caller-supplied
 *           AES-CCM key.
 *
 * @return  Shared block point of the decrypted content, if decryption and
 *          authentication succeed.
 * @return  NULL, if @p block is NULL or malformed.
 * @return  NULL, if @p key is NULL.
 * @return  NULL, if @p key_len is not NDN_DATA_CCM_KEY_LEN.
 * @return  NULL, if cipher API returns failure.
 */
ndn_shared_block_t* ndn_data_decrypt_with_ccm(ndn_block_t* block,
					      const uint8_t* key,
					      uint8_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* NDN_DATA_H_ */
/** @} */
