/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_SEC_INTF_SETTER_H
#define SIGN_ON_BASIC_SEC_INTF_SETTER_H

#include <stdint.h>
#include <stddef.h>

#include "sign-on-basic-client.h"

/**@brief Function to set the security interface of a Sign-on Basic client. Security implementations of 
 *          generic security operations in the Sign-on Basic client will depend on the variant.
 *
 * @param[in]   variant                    Variant type that security implementation will be based on.
 * @param[in]   sign_on_basic_client       Reference to sign_on_basic_client_t to set the security interfaces
 *                                           of.
 *
 * @return      Returns NDN_SUCCESS upon success.
 */
int sign_on_basic_set_sec_intf(uint8_t variant, struct sign_on_basic_client_t *sign_on_basic_client);

#endif // SIGN_ON_BASIC_SEC_INTF_SETTER_H
