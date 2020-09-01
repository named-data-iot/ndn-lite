/*
 * Copyright (C) 2019 Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */
#ifndef NDN_LITE_H
#define NDN_LITE_H

#include "ndn-lite/ndn-constants.h"
#include "ndn-lite/ndn-enums.h"
#include "ndn-lite/ndn-error-code.h"
#include "ndn-lite/ndn-services.h"
#include "ndn-lite/encode/key-storage.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/encode/wrapper-api.h"
#include "adaptation/adapt-consts.h"
#include "adaptation/udp/udp-face.h"
#include "adaptation/unix-socket/unix-face.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void
ndn_lite_startup(void);

#ifdef __cplusplus
};
#endif

#endif // NDN_LITE_H
