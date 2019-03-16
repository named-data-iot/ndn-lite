/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */
#ifndef FORWARDER_CALLBACK_FUNCS_H
#define FORWARDER_CALLBACK_FUNCS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The onInterest callback function.
 * 
 * @param interest [in] The encoded interest.
 * @param interest_size [in] The length of the @c interest .
 * @param userdata [in] User defined data.
 * @return The action to take. (Unused now)
 */
typedef int (*ndn_on_interest_func)(const uint8_t* interest,
                                    uint32_t interest_size,
                                    void* userdata);

/** The onData callback function.
 * 
 * @param data [in] The encoded data.
 * @param data_size [in] The length of the @c data .
 * @param userdata [in] User defined data.
 */
typedef void (*ndn_on_data_func)(const uint8_t* data, uint32_t data_size, void* userdata);

/** The onTimeout callback function.
 * 
 * @param userdata [in] User defined data.
 */
typedef void (*ndn_on_timeout_func)(void* userdata);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_CALLBACK_FUNCS_H
