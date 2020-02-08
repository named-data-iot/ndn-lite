/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_SERVICES_H
#define NDN_SERVICES_H

#include <stdint.h>

// service types: 0-10 preserved for ndn-lite system default
#define NDN_SD_NONE ((uint8_t)(-1))
#define NDN_SD_DEV_CTL 0 // device control service, (ideally) run by ALL devices
#define NDN_SD_SD 1 // service discovery service, (ideally) run by ALL devices
#define NDN_SD_SD_CTL 2 // service discovery control service, run by authorized devices ONLY
#define NDN_SD_AC 3 // access control service, run by authorized devices ONLY

// service types: >10, <255 application services
#define NDN_SD_LED 11 // LED service
#define NDN_SD_TEMP 12 // temperature service

// per-service command types
// DEV_CTL service
#define NDN_SD_DEV_ADV false // no advertisement
#define NDN_SD_DEV_CTL_ON 0 // turn on device
#define NDN_SD_DEV_CTL_OFF 1 // turn off device
#define NDN_SD_DEV_CTL_RESTART 2 // restart device
#define NDN_SD_DEV_CTL_SLEEP 3 // enter sleep mode
#define NDN_SD_DEV_CTL_AWAKE 4 // awake from sleep mode
#define NDN_SD_DEV_CTL_STATUS 5 // read status of the device

// SD service
#define NDN_SD_SD_ADV false // no advertisement
#define NDN_SD_SD_AD 0 // advertisement of self services
#define NDN_SD_SD_QUERY 1 // query services provided by the system

// SD_CTL service
#define NDN_SD_SD_CTL_ADV false // no advertisement
#define NDN_SD_SD_CTL_META 0 // query meta info of services in the system

// AC service
#define NDN_SD_AC_ADV false // no advertisement
#define NDN_SD_AC_EK 0 // query an encryption key from the SP
#define NDN_SD_AC_DK 1 // query a decryption key from the SP

#endif // NDN_SERVICES_H