/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef FORWARDER_CALLBACK_FUNCS_H
#define FORWARDER_CALLBACK_FUNCS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The onInterest callback function.
 *
 * @param[in] interest The encoded interest.
 * @param[in] interest_size The length of the @c interest .
 * @param[in] userdata [Optional] User defined data.
 * @return The forward strategy to take, only used if no Data get from this function.
 */
typedef int (*ndn_on_interest_func)(const uint8_t* interest,
                                    uint32_t interest_size,
                                    void* userdata);

/** The onData callback function.
 *
 * @param[in] data The encoded data.
 * @param[in] data_size The length of the @c data .
 * @param[in] userdata [Optional] User defined data.
 */
typedef void (*ndn_on_data_func)(const uint8_t* data, uint32_t data_size, void* userdata);

/** The onTimeout callback function.
 *
 * @param[in] userdata [Optional] User defined data.
 */
typedef void (*ndn_on_timeout_func)(void* userdata);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_CALLBACK_FUNCS_H
