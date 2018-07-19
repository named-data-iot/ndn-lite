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

/**
 * @brief   Check whether a Data packet name follows certificate naming convention
 *
 * @param[in]   cert_name  The name to be checked
 *
 * @return  0 if the @p cert_name is a certificate name
 * @return  -1 if not
 */
int
ndn_cert_is_certificate_name(ndn_name_t* cert_name);

/**
 * @brief   Extract the identity name from a given certificate name
 *
 * @param[in]   cert_name     Certificate name
 * @param[out]  identity_name Identity name
 *
 * @return  0 if success
 * @return -1 if cert_name is invalid
 */
int
ndn_cert_get_identity_name(ndn_name_t* cert_name, ndn_name_t* identity_name);

/**
 * @brief   Extract the key name from a given certificate name
 *
 * @param[in]   cert_name  Certificate name
 * @param[out]  key_name   Key name
 *
 * @return  0 if success
 * @return -1 if cert_name is invalid
 */
int
ndn_cert_get_key_name(ndn_name_t* cert_name, ndn_name_t* key_name);


#ifdef __cplusplus
}
#endif

#endif // NDN_CERTIFICATE_H_
