/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_ERROR_CODE_H
#define NDN_ERROR_CODE_H

// General Error Types
#define NDN_OVERSIZE -10
#define NDN_NAME_INVALID_FORMAT -11
#define NDN_WRONG_TLV_TYPE -12
#define NDN_OVERSIZE_VAR -13

// Security Error
#define NDN_SEC_WRONG_KEY_SIZE -22
#define NDN_SEC_WRONG_SIG_SIZE -23
#define NDN_SEC_NOT_ENABLED_FEATURE -24
#define NDN_SEC_CRYPTO_ALGO_FAILURE -25
#define NDN_SEC_UNSUPPORT_CRYPTO_ALGO -26
#define NDN_SEC_UNSUPPORT_SIGN_TYPE -26
#define NDN_SEC_WRONG_AES_SIZE -27

// Fragmentation Error
#define NDN_FRAG_NO_MORE_FRAGS -30
#define NDN_FRAG_OUT_OF_ORDER -31
#define NDN_FRAG_NOT_ENOUGH_MEM -32
#define NDN_FRAG_WRONG_IDENTIFIER -33

// Forwarder Error
#define NDN_FWD_INSUFFICIENT_MEMORY -40
#define NDN_FWD_PIT_FULL -41
#define NDN_FWD_PIT_ENTRY_FACE_LIST_FULL -42
#define NDN_FWD_FIB_FULL -43
#define NDN_FWD_INTEREST_REJECTED -44
#define NDN_FWD_NO_MATCHED_CALLBACK -45

// Face Error
#define NDN_FWD_APP_FACE_CB_TABLE_FULL -50

#endif // NDN_ERROR_CODE_H
