/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#ifndef NDN_APP_SUPPORT_SIG_VERIFIER_H
#define NDN_APP_SUPPORT_SIG_VERIFIER_H

#include "../encode/interest.h"
#include "../encode/data.h"
#include "../forwarder/forwarder.h"

typedef int (*on_int_verification_success)(ndn_interest_t* interest);
typedef int (*on_int_verification_failure)(ndn_interest_t* interest);
typedef int (*on_data_verification_success)(ndn_data_t* interest);
typedef int (*on_data_verification_failure)(ndn_data_t* interest);

// init the verifier with a face for self prefix-registration and cert interest sending
// is supposed to be invoked after bootstrapping
int
ndn_sig_verifier_init(ndn_face_intf_t* face);

// if the needed key is not in the key storage
// will send interest to fetch certificate to proceed verification
void
ndn_sig_verifier_verify_int(const uint8_t* raw_pkt, size_t pkt_size, ndn_interest_t* interest,
                            on_int_verification_success on_success,
                            on_int_verification_failure on_failure);

void
ndn_sig_verifier_verify_data(const uint8_t* raw_pkt, size_t pkt_size, ndn_data_t* data,
                             on_data_verification_success on_success,
                             on_data_verification_failure on_failure);

#endif // NDN_APP_SUPPORT_SIG_VERIFIER_H