/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef logger_h
#define logger_h

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_NDN_LOG_ERROR
#define NDN_LOG_ERROR(...) { \
  printf("ERROR: %s, L%d: ", __func__, __LINE__); \
  printf(__VA_ARGS__);printf("\n"); \
}
#else
#define NDN_LOG_ERROR(...)
#endif

#ifdef ENABLE_NDN_LOG_DEBUG
#define NDN_LOG_DEBUG(...) { \
  printf("DEBUG: %s, L%d: ", __func__, __LINE__); \
  printf(__VA_ARGS__);printf("\n"); \
}
#else
#define NDN_LOG_DEBUG(...)
#endif

#ifdef ENABLE_NDN_LOG_INFO
#define NDN_LOG_INFO(...) { \
  printf(__VA_ARGS__);printf("\n"); \
}
#else
#define NDN_LOG_INFO(...)
#endif

/*@}*/

#ifdef __cplusplus
}
#endif

#endif /* logger_h */