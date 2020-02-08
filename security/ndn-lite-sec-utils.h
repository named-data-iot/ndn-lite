/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_SECURITY_UTILS_H_
#define NDN_SECURITY_UTILS_H_

#include <inttypes.h>
#include <stdbool.h>

int
ndn_const_time_memcmp(const uint8_t* a, const uint8_t* b, uint32_t size);

/**
 * Encode a signature in the format used by the micro-ecc format; final encoding
 * will be in ASN.1, DER format.
 * The curve type of signature will be inferred from the length of the signature passed in.
 * @param raw_ecdsa_sig. Input. Signature to be encoded, in the format used by the
 *                                micro-ecc library.
 * @param raw_ecdsa_sig_len. Input. Length of the signature. Should be even.
 * @param raw_ecdsa_sig_buf_len. Input. Length of the buffer containing the signature. Should
 *                                        be long enough to hold final encoding.
 * @return NDN_SUCCESS if there is no error.
 */
int
ndn_asn1_encode_ecdsa_signature(uint8_t* raw_ecdsa_sig, uint32_t raw_ecdsa_sig_len,
                                uint32_t raw_ecdsa_sig_buf_len);

/**
 * Probe the size that an ecdsa signature in the same format used by the micro-ecc library will
 *   have if it is encoded in ASN.1 DER format.
 * The curve type of signature will be inferred from the length of the signature passed in.
 * @param raw_ecdsa_sig. Input. Signature to check the ASN.1 encoded length of, in the format used by the
 *                                micro-ecc library.
 * @param raw_ecdsa_sig_len. Input. Length of the signature. Should be even.
 * @param encoded_ecdsa_sig_len. Output. Length that signature will be if ASN.1 encoded. Will only be
 *                                         populated if there is no error.
 * @return NDN_SUCCESS if there is no error.
 */
int
ndn_asn1_probe_ecdsa_signature_encoding_size(const uint8_t *raw_ecdsa_sig, uint32_t raw_ecdsa_sig_len,
                                             uint32_t *encoded_ecdsa_sig_len);

/**
 * Decode a signature in ASN.1, DER format into the format used by the micro-ecc library.
 * The curve type of signature will be inferred from the length of the signature passed in.
 * @param encoded_ecdsa_sig. Input. Signature to be decoded, in ASN.1 DER format.
 * @param encoded_ecdsa_sig_len. Input. Length of the encoded signature.
 * @param decoded_ecdsa_sig. Output. Length of the buffer to store decoded signature. Should
 *                                        be long enough to hold final decoding.
 * @param decoded_ecdsa_sig_buf_len. Input. Length of buffer to hold decoded signature.
 * @param raw_ecdsa_sig_len. Output. Length of the decoded signature, in the same format used
 *                                   by the micro-ecc library.
 * @return NDN_SUCCESS if there is no error.
 */
int
ndn_asn1_decode_ecdsa_signature(const uint8_t *encoded_ecdsa_sig, uint32_t encoded_ecdsa_sig_len,
                                uint8_t *decoded_ecdsa_sig, uint32_t decoded_ecdsa_sig_buf_len,
                                uint32_t *raw_ecdsa_sig_len);

#endif // NDN_SECURITY_UTILS_H_
