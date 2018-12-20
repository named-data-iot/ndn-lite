/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_ACCESS_CONTROL_H
#define NDN_APP_SUPPORT_ACCESS_CONTROL_H

#include "../encode/interest.h"
#include "../encode/data.h"

typedef struct ndn_ac_unfinished_key {
  uint32_t key_id;
  ndn_ecc_pub_t dh_pub;
  ndn_ecc_prv_t dh_prv;
} ndn_ac_unfinished_key_t;

typedef struct ndn_ac_state {
  ndn_name_t self_identity;

  // self identity key
  ndn_ecc_pub_t self_pub_key;
  ndn_ecc_prv_t self_prv_key;

  // aes key ids
  uint32_t eks[NDN_APPSUPPORT_AC_KEY_LIST_SIZE];
  uint32_t dks[NDN_APPSUPPORT_AC_KEY_LIST_SIZE];
} ndn_ac_state_t;

void
ndn_ac_state_init(const ndn_name_t* self_identity, const ndn_ecc_pub_t* self_pub_key,
                  const ndn_ecc_prv_t* self_prv_key);

int
ndn_ac_prepare_key_request_interest(ndn_encoder_t* encoder,
                                    const ndn_name_t* home_prefix,
                                    const name_component_t* self_identity,
                                    uint32_t ac_key_id, const ndn_ecc_prv_t* prv_key,
                                    uint8_t is_ek);

int
ndn_ac_on_ek_response_process(const ndn_data_t* data);

int
ndn_ac_on_dk_response_process(const ndn_data_t* data);


//controller part
int
ndn_ac_on_interest_process(ndn_data_t* response, const ndn_interest_t* interest);

int
ndn_ac_prepare_ek_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
                           ndn_data_t* response);

int
ndn_ac_prepare_dk_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
                           ndn_data_t* response);

/*
  int
  ndn_ac_check_policy
*/

// #ifdef __cplusplus
// }
// #endif

#endif // NDN_APP_SUPPORT_ACCESS_CONTROL_H
