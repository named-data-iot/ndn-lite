/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NDN_FORWARDER_ERROR_CODE_H
#define NDN_FORWARDER_ERROR_CODE_H

// Forwarder error codes
#define NDN_FWD_ERROR_INSUFFICIENT_MEMORY -50
#define NDN_FWD_ERROR_PIT_FULL -51
#define NDN_FWD_ERROR_PIT_ENTRY_FACE_LIST_FULL -53
#define NDN_FWD_ERROR_FIB_FULL -52

#define NDN_FWD_ERROR_INTEREST_REJECTED -62


#define NDN_FWD_NO_MATCHED_CALLBACK -63
#define NDN_FWD_APP_FACE_CB_TABLE_FULL -64

#endif // NDN_FORWARDER_ERROR_CODE_H
