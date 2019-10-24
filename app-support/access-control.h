/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_ACCESS_CONTROL_H
#define NDN_APP_SUPPORT_ACCESS_CONTROL_H

#include "../encode/interest.h"
#include "../encode/data.h"

// Basic Design:
// 1. The access control policy are decided by schema
// 2. The access control key can be roll overed by existing key (e.g., through one-way function)
// 3. The access control granularity can be kept in the service type level at the moment

void
register_service_require_ek(uint8_t service);

void
register_access_request(uint8_t service);

void
ac_after_bootstrapping();

#endif // NDN_APP_SUPPORT_ACCESS_CONTROL_H