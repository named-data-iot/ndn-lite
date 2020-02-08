/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_SIGNED_INTEREST_H
#define NDN_ENCODING_SIGNED_INTEREST_H

#include "interest.h"
#include "../security/ndn-lite-hmac.h"
#include "../security/ndn-lite-sha.h"
#include "../security/ndn-lite-ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Use Digest (SHA256) to sign the Interest.
 * This function will automatically set signature info and signature value.
 * @param interest. Input. The Interest to be signed and encoded.
 * @return 0 if there is no error.
 */
int
ndn_signed_interest_digest_sign(ndn_interest_t* interest);

/**
 * Use ECDSA Algorithm to sign the Interest and encode the Signed Interest into wire format.
 * This function will automatically set signature info and signature value.
 * @param encoder. Output. The encoder to keep the encoded Signed Interest.
 *        The encoder should be inited to proper output buffer.
 * @param interest. Input. The Interest to be signed and encoded.
 * @param identity. Input. The producer's identity name. Can be NULL.
 * @param prv_key. Input. The private ECC key used to generate the signature. Can be NULL.
 * @return 0 if there is no error.
 */
int
ndn_signed_interest_ecdsa_sign(ndn_interest_t* interest,
                               const ndn_name_t* identity,
                               const ndn_ecc_prv_t* prv_key);

/**
 * Use HMAC Algorithm to sign the Interest and encode the Signed Interest into wire format.
 * This function will automatically set signature info and signature value.
 * @param encoder. Output. The encoder to keep the encoded Signed Interest.
 *        The encoder should be inited to proper output buffer.
 * @param interest. Input. The Interest to be signed and encoded.
 * @param identity. Input. The producer's identity name.
 * @param prv_key. Input. The private HMAC key used to generate the signature.
 * @return 0 if there is no error.
 */
int
ndn_signed_interest_hmac_sign(ndn_interest_t* interest,
                              const ndn_name_t* identity,
                              const ndn_hmac_key_t* hmac_key);

/**
 * Verify the Digest (SHA256) signature of a decoded Signed Interest.
 * @param interest. Input. The decoded Signed Interest whose signature to be verified.
 * @return 0 if there is no error and the signature is valid.
 */
int
ndn_signed_interest_digest_verify(const ndn_interest_t* interest);

/**
 * Verify the ECDSA signature of a decoded Signed Interest.
 * @param interest. Input. The decoded Signed Interest whose signature to be verified.
 * @param pub_key. Input. The ECC public key used to verify the Signed Interest signature.
 * @return 0 if there is no error and the signature is valid.
 */
int
ndn_signed_interest_ecdsa_verify(const ndn_interest_t* interest,
                                 const ndn_ecc_pub_t* pub_key);

/**
 * Verify the HMAC signature of a decoded Signed Interest.
 * @param interest. Input. The decoded Signed Interest whose signature to be verified.
 * @param hmac_key. Input. The HMAC public key used to verify the Signed Interest signature.
 * @return 0 if there is no error and the signature is valid.
 */
int
ndn_signed_interest_hmac_verify(const ndn_interest_t* interest,
                                const ndn_hmac_key_t* hmac_key);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_SIGNED_INTEREST_H
