/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_ndn_encoding
 * @{
 *
 * @file
 *
 * @author  Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_H_
#define NDN_CERTIFICATE_H_

#include "ndn-constants.h"
#include "name.h"
#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int
ndn_cert_is_certificate_name(ndn_name_t* block);

int
ndn_cert_get_identity_name(ndn_name_t* cert_name, ndn_name_t* identity_name);

int
ndn_cert_get_key_name(ndn_name_t* cert_name, ndn_name_t* key_name);


#ifdef __cplusplus
}
#endif

#endif // NDN_CERTIFICATE_H_
