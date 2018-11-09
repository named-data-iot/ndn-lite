/*
 * Copyright (C) 2018 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef error_code_h
#define error_code_h

// Forwarder error codes
#define NDN_FWD_ERROR_INSUFFICIENT_MEMORY -50
#define NDN_FWD_ERROR_PIT_FULL            -51
#define NDN_FWD_ERROR_FIB_FULL            -52
// TODO: Maybe we need different codes for no entry slots & no face slots in entry

#define NDN_FWD_ERROR_INTEREST_REJECTED   -62

#define NDN_FWD_INVALID_NAME_SIZE         ((uint32_t)(-1))

#endif /* error_code_h */
