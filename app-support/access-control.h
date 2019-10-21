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

// void
// ac_after_bootstrapping(ndn_face_intf_t* face); // which is to load one’s own produced data prefixes into the state

// void
// _construct_ekey_interest(uint8_t service)
// {
//   // send /home/AC/EKEY/<the service provided by my self> to the controller
//   // sign
// }

// void
// _construct_dkey_interest(uint8_t service)
// {
//   // send /home/AC/DKEY/<the services that I need to access> to the controller
//   // sign
// }

// void
// _on_ekey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
// {
//   // parse Data
//   // get key: decrypt the key
//   // store it into key_storage
// }

// void
// _on_dkey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
// {
//   // parse Data
//   // get key: decrypt the key
//   // store it into key_storage
// }

void
register_service_require_ek(uint8_t service);

void
register_access_request(uint8_t service);

void
ac_after_bootstrapping(ndn_face_intf_t* face)
{
  // send /home/AC/EKEY/<the service provided by my self> to the controller
  // send /home/AC/DKEY/<the services that I need to access> to the controller
  // e.g. Temp sensor produce under TEMP, access SD
  // 1. send /home/AC/EKEY/TEMP to obtain encryption key
  // 2. send /home/AC/DKEY/SD to obtain decryption key
}

#endif // NDN_APP_SUPPORT_ACCESS_CONTROL_H