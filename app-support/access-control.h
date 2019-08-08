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

const static uint32_t KEY_ROLLOVER_AHEAD_TIME = 86400000;

void
ac_init_state(const name_component_t* home_prefix); //  which is to load one’s own produced data prefixes into the state

void
ac_add_data_prefix_need_ek(const ndn_name_t* data_prefix);

int
ac_get_ek_for_prefix(const ndn_name_t* data_prefix, ndn_aes_key_t* ek);

int
ac_get_dk(const ndn_name_t* key_prefix, ndn_aes_key_t* dk);

void
ac_start_auto_key_rollover();

void
ac_apply_ek();

void
ac_apply_dk(const ndn_name_t* key_name, bool one_time);


// /**
//  * Init a Access Control State structure.
//  * @param self_identity. Input. Local state manager identity.
//  * @param self_pub_key. Input. The identity ECC public key.
//  * @param self_prv_key. Input. The identity ECC private key.
//  */
// void
// ndn_ac_state_init(const ndn_name_t* self_identity, const ndn_ecc_pub_t* self_pub_key,
//                   const ndn_ecc_prv_t* self_prv_key);

// /**
//  * Prepare a Key Request to send. This function will automatically sign and encode the interest.
//  * @param encoder. Output. The encoder to keep the encoded Key Request.
//  *        The encoder should be inited to proper output buffer.
//  * @param home_prefix. Input. The network home prefix to configure the state manager.
//  * @param self_identity. Input. The local state manager identity.
//  * @param prv_key. Input. The ECC private key used to sign the interest.
//  * @param is_ek. Input. Determine whether to encode a Encryption Request or Decryption Request.
//  * @return 0 if there is no error.
//  */
// int
// ndn_ac_prepare_key_request_interest(ndn_encoder_t* encoder,
//                                     const ndn_name_t* home_prefix,
//                                     const name_component_t* self_identity,
//                                     uint32_t ac_key_id, const ndn_ecc_prv_t* prv_key,
//                                     uint8_t is_ek);

// /**
//  * Process Encryption Request's Response. This function will automatically set and
//  * update Access Control State.
//  * @param data. Input. Decoded and signature verified Encryption Request's Response Packet.
//  * @return 0 if there is no error.
//  */
// int
// ndn_ac_on_ek_response_process(const ndn_data_t* data);

// /**
//  * Process Deryption Request's Response. This function will automatically set and
//  * update Access Control State.
//  * @param data. Input. Decoded and signature verified Decryption Request's Response Packet.
//  * @return 0 if there is no error.
//  */
// int
// ndn_ac_on_dk_response_process(const ndn_data_t* data);

// /*************************/
// /*  APIs for Controller  */
// /*************************/

// /**
//  * Process Access Control Request. This function will automatically set and
//  * update Access Control State on the access controller side.
//  * @param response. Output. Prepared Response.
//  * @param interest. Input. Decoded and signature verified signed interest.
//  * @return 0 if there is no error.
//  */
// int
// ndn_ac_on_interest_process(ndn_data_t* response, const ndn_interest_t* interest);

// /*************************************/
// /*  Helper Functions for Controller  */
// /*************************************/
// int
// ndn_ac_prepare_ek_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
//                            ndn_data_t* response);

// int
// ndn_ac_prepare_dk_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
//                            ndn_data_t* response);


#endif // NDN_APP_SUPPORT_ACCESS_CONTROL_H
