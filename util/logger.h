/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef logger_h
#define logger_h

#include <stdio.h>
#include <stdlib.h>
#include "../encode/name.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ENABLE_NDN_LOG_ERROR
#define NDN_LOG_ERROR(...) { \
  printf("ERROR: %s, L%d: ", __func__, __LINE__); \
  printf(__VA_ARGS__); \
}
#define NDN_LOG_ERROR_NAME(name) { \
  ndn_name_print(name);\
}
#else
#define NDN_LOG_ERROR(...)
#define NDN_LOG_ERROR_NAME(name)
#endif

#if ENABLE_NDN_LOG_DEBUG
#define NDN_LOG_DEBUG(...) { \
  printf("DEBUG: %s, L%d: ", __func__, __LINE__); \
  printf(__VA_ARGS__); \
}
#define NDN_LOG_DEBUG_NAME(name) { \
  ndn_name_print(name);\
}
#else
#define NDN_LOG_DEBUG(...)
#define NDN_LOG_DEBUG_NAME(name)
#endif

#if ENABLE_NDN_LOG_INFO
#define NDN_LOG_INFO(...) { \
  printf("INFO: %s: ", __func__); \
  printf(__VA_ARGS__);printf("\n"); \
}
#define NDN_LOG_INFO_NAME(name) { \
  ndn_name_print(name);\
}
#define NDN_LOG_INFO_NO_NEWLINE(...) { \
  printf(__VA_ARGS__); \
}
#else
#define NDN_LOG_INFO(...)
#define NDN_LOG_INFO_NAME(name)
#define NDN_LOG_INFO_NO_NEWLINE(...)
#endif

/*@}*/

#ifdef __cplusplus
}
#endif

#endif /* logger_h */