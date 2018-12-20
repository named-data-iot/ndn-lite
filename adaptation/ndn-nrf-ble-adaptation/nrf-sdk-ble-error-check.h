/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NRF_SDK_BLE_ERROR_CHECK_H
#define NRF_SDK_BLE_ERROR_CHECK_H

#include "logger.h"
#include "app_error.h"

/**@brief Macro for calling error handler function if supplied error code any other than NRF_SUCCESS or NRF_ERROR_INVALID_STATE
 *
 * @param[in] ERR_CODE Error code supplied to the error handler.
 */
#define APP_ERROR_CHECK_IGNORE_INVALID_STATE(ERR_CODE, msg)                                   \
  do {                                                                                        \
    APP_LOG("APP_ERROR_CHECK_IGNORE_INVALID_STATE got called, msg: %s\n", msg);               \
    if (ERR_CODE == NRF_ERROR_INVALID_STATE) {                                                \
      APP_LOG("Detected NRF_ERROR_INVALID_STATE in APP_ERROR_CHECK_IGNORE_INVALID_STATE.\n"); \
    }                                                                                         \
    const uint32_t LOCAL_ERR_CODE = (ERR_CODE);                                               \
    if (LOCAL_ERR_CODE != NRF_SUCCESS && LOCAL_ERR_CODE != NRF_ERROR_INVALID_STATE) {         \
      APP_ERROR_HANDLER(LOCAL_ERR_CODE);                                                      \
    }                                                                                         \
  } while (0)

#endif // NRF_SDK_BLE_ERROR_CHECK_H