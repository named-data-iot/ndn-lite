/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_APP_SUPPORT_SIG_VERIFIER_H
#define NDN_APP_SUPPORT_SIG_VERIFIER_H

#include "../encode/interest.h"
#include "../encode/data.h"
#include "../forwarder/forwarder.h"

/** Sig Verifier Spec
 *
 *  Verifier is to verify Interest/Data packet signature and automatically fetch certificates if needed.
 *  When verifying a incoming Interest/Data packet:
 *  if HMAC signature:
 *  1. find local HMAC key storage using the key_id, if not found, fail.
 *  2. use the key to verify the signature, if valid, succeed; otherwise, fail.
 *
 *  if ECDSA signature:
 *  1. find local ECC pub key storage using the key_id
 *    i. if not found, send out an Interest to fetch the certificate => move to step 2
 *    ii. otherwise, use the key to verify the signature, if valid, succeed; otherwise, fail.
 *  2. using the trust anchor key to verify the certificate, if invalid, fail; otherwise => move to step 3
 *  3. load the recevied certificate into trusted keys in local key storage and use the cert to verify the original
 *    packet. If valid, succeed; otherwise, fail.
 *
 * TODO: check validity period when checking receive certificate
 */

typedef void (*on_int_verification_success)(ndn_interest_t* interest, void* userdata);
typedef void (*on_int_verification_failure)(ndn_interest_t* interest, void* userdata);
typedef void (*on_data_verification_success)(ndn_data_t* data, void* userdata);
typedef void (*on_data_verification_failure)(ndn_data_t* data, void* userdata);

// init the verifier with a face for self prefix-registration and cert interest sending
// is supposed to be invoked after bootstrapping
void
ndn_sig_verifier_after_bootstrapping(ndn_face_intf_t* face);

// if the needed key is not in the key storage
// will send interest to fetch certificate to proceed verification
void
ndn_sig_verifier_verify_int(const uint8_t* raw_pkt, size_t pkt_size,
                            on_int_verification_success on_success, void* on_success_userdata,
                            on_int_verification_failure on_failure, void* on_failure_userdata);

void
ndn_sig_verifier_verify_data(const uint8_t* raw_pkt, size_t pkt_size,
                             on_data_verification_success on_success, void* on_success_userdata,
                             on_data_verification_failure on_failure, void* on_failure_userdata);

#endif // NDN_APP_SUPPORT_SIG_VERIFIER_H