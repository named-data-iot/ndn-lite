/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_CLIENT_CONSTS_H
#define SIGN_ON_BASIC_CLIENT_CONSTS_H

/** @defgroup Sign on process completion statuses for the sign on basic client.
 * @{ */
#define SIGN_ON_BASIC_CLIENT_NOT_STARTED 0 ///< The sign-on process has not started for this client yet.
#define SIGN_ON_BASIC_CLIENT_GENERATED_BOOTSTRAPPING_REQUEST 1 ///< A bootstrapping request has been successfully generated.
#define SIGN_ON_BASIC_CLIENT_PROCESSED_BOOTSTRAPPING_REQUEST_RESPONSE 2 ///< A bootstrapping request response has been successfully processed, and been confirmed as valid.
#define SIGN_ON_BASIC_CLIENT_GENERATED_CERTIFICATE_REQUEST 3 ///< A certificate request has been successfully generated.
#define SIGN_ON_BASIC_CLIENT_PROCESSED_CERTIFICATE_REQUEST_RESPONSE 4 ///< A certificate request response has been successfully processed, and has been confirmed as valid.
#define SIGN_ON_BASIC_CLIENT_GENERATED_FINISH_MESSAGE 5 ///< A finish message has been successfully generated.
/** @} */

#define SIGN_ON_BASIC_CLIENT_DEVICE_IDENTIFIER_MAX_LENGTH 12 ///< Length that sign_on_basic_client_t will preallocate for device identifier

#define SIGN_ON_BASIC_CLIENT_DEVICE_CAPABILITIES_MAX_LENGTH 1 ///< Length that sign_on_basic_client_t will preallocate for device capabilities

#define SIGN_ON_BASIC_CLIENT_SECURE_SIGN_ON_CODE_MAX_LENGTH 16 ///< Length that sign_on_basic_client_t will preallocate for secure sign-on code

#define SIGN_ON_BASIC_CLIENT_KD_PUB_CERT_MAX_LENGTH 200 ///< Length that sign_on_basic_client_t will preallocate for KD public key certificate

#define SIGN_ON_BASIC_CLIENT_TRUST_ANCHOR_CERT_MAX_LENGTH 200 ///< Length that sign_on_basic_client_t will preallocate for trust anchor certificate

#define SIGN_ON_BASIC_CLIENT_KS_PUB_MAX_LENGTH 384 ///< Length that sign_on_basic_client_t will preallocate for KS public key
#define SIGN_ON_BASIC_CLIENT_KS_PRI_MAX_LENGTH 172 ///< Length that sign_on_basic_client_t will preallocate for KS private key

#define SIGN_ON_BASIC_CLIENT_N1_PUB_MAX_LENGTH 384 ///< Length that sign_on_basic_client_t will preallocate for N1 keypair public key
#define SIGN_ON_BASIC_CLIENT_N1_PRI_MAX_LENGTH 172 ///< Length that sign_on_basic_client_t will preallocate for N1 keypair private key

#define SIGN_ON_BASIC_CLIENT_N2_PUB_MAX_LENGTH 384 ///< Length that sign_on_basic_client_t will preallocate for N2 keypair public key

#define SIGN_ON_BASIC_CLIENT_KD_PUB_MAX_LENGTH 384 ///< Length that sign_on_basic_client_t will preallocate for KD public key
#define SIGN_ON_BASIC_CLIENT_KD_PRI_MAX_LENGTH 172 ///< Length that sign_on_basic_client_t will preallocate for KD private key

#define SIGN_ON_BASIC_CLIENT_KT_MAX_LENGTH 172 ///< Length that sign_on_basic_client_t will preallocate for KT

#endif // SIGN_ON_BASIC_CLIENT_CONSTS_H
