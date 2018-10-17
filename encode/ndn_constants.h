/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef ENCODING_NDN_CONSTANTS_H
#define ENCODING_NDN_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif


// buffer and block memory allocation
#define NAME_COMPONENT_BUFFER_SIZE 72
#define NAME_COMPONENT_BLOCK_SIZE 74
#define NDN_NAME_COMPONENTS_SIZE 10
#define NDN_NAME_BLOCK_SIZE 724

#define NDN_INTEREST_PARAMS_BUFFER_SIZE 200


// default values
#define DEFAULT_INTEREST_LIFETIME 4000



// error messages
#define NDN_ERROR_OVERSIZE -10
#define NDN_ERROR_NAME_INVALID_FORMAT -11

#ifdef __cplusplus
}
#endif

#endif // ENCODING_NDN_CONSTANTS_H
