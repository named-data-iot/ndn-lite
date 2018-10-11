/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ndn    NDN
 * @ingroup     net
 * @brief       NDN implementation for RIOT-OS.
 * @{
 *
 * @file
 * @brief   NDN TLV-related utilities.
 *
 * @author  Wentao Shang <wentaoshang@gmail.com>
 */
#ifndef NDN_TLV_CONSTANTS_H_
#define NDN_TLV_CONSTANTS_H_

#ifdef __cplusplus
extern "C" {
#endif

/* 32 bytes for token bits */
#define NDN_CRYPTO_TOKEN 32

/* 32 bytes for hash bits */
#define NDN_CRYPTO_HASH 32

/* common symmetric key size used in NDN */
#define NDN_CRYPTO_SYMM_KEY 32

/* common asymmetric public key size used in NDN */
#define NDN_CRYPTO_ASYMM_PUB 64

/* common asymmetric private key size used in NDN */
#define NDN_CRYPTO_ASYMM_PVT 32

/* AES-128 encryption key size */
#define NDN_CRYPTO_AES_SIZE 16

enum {
    /* Basic TLVs */
    NDN_TLV_INTEREST         = 5,
    NDN_TLV_DATA             = 6,
    NDN_TLV_NAME             = 7,
    NDN_TLV_NAME_COMPONENT   = 8,

    /* Interest-related TLVs */
    NDN_TLV_SELECTORS        = 9,
    NDN_TLV_NONCE            = 10,
    NDN_TLV_INTERESTLIFETIME = 12,

    /* Data-related TLVs */
    NDN_TLV_METAINFO         = 20,
    NDN_TLV_CONTENT          = 21,
    NDN_TLV_SIGNATURE_INFO   = 22,
    NDN_TLV_SIGNATURE_VALUE  = 23,

    /* Metainfo-related TLVs */
    NDN_TLV_CONTENT_TYPE     = 24,
    NDN_TLV_FRESHNESS_PERIOD = 25,
    NDN_TLV_CCM_NONCE        = 30,

    /* Signature-related TLVs */
    NDN_TLV_SIGNATURE_TYPE   = 27,
    NDN_TLV_KEY_LOCATOR      = 28,
    
    /* Special-used TLVs */
    NDN_TLV_BLOB = 29,
};


/* content type values */
enum {
    NDN_CONTENT_TYPE_BLOB = 0,
    NDN_CONTENT_TYPE_LINK = 1,
    NDN_CONTENT_TYPE_KEY  = 2,
    NDN_CONTENT_TYPE_NACK = 3,
    NDN_CONTENT_TYPE_CCM  = 50,
};

/* signature type values */
enum {
    NDN_SIG_TYPE_DIGEST_SHA256 = 0,
    NDN_SIG_TYPE_ECDSA_SHA256  = 3,
    NDN_SIG_TYPE_HMAC_SHA256   = 4,
};

#ifdef __cplusplus
}
#endif

#endif /* NDN_TLV_CONSTANTS_H_ */
/** @} */
