
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ASN_ENCODE_DECODE_TESTS_DEF_H
#define ASN_ENCODE_DECODE_TESTS_DEF_H

#include "asn-encode-decode-tests.h"

#define ASN_ENCODE_DECODE_NUM_TESTS 4

extern char *asn_encode_decode_test_names[ASN_ENCODE_DECODE_NUM_TESTS];

extern bool asn_encode_decode_test_results[ASN_ENCODE_DECODE_NUM_TESTS];

extern asn_encode_decode_test_t asn_encode_decode_tests[ASN_ENCODE_DECODE_NUM_TESTS];


// testing the maximum signature size
////////////////////////////////////////////////////////////////////////////////////////

// first integer requires padding, second integer requires padding
#define test_sig_5_asn_encoded_probe_length_expected (uint32_t) (NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE)
extern uint8_t test_sig_5[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE];
extern uint8_t test_sig_5_asn_encoded_expected[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE];
extern uint8_t test_sig_5_decoded[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];
extern uint8_t test_sig_5_decoded_expected[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];

// first integer requires no padding, second integer requires no padding
#define test_sig_6_asn_encoded_probe_length_expected (uint32_t) (NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE - 2)
extern uint8_t test_sig_6[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE];
extern uint8_t test_sig_6_asn_encoded_expected[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE - 2];
extern uint8_t test_sig_6_decoded[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];
extern uint8_t test_sig_6_decoded_expected[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];

// first integer requires padding, second integer requires no padding
#define test_sig_7_asn_encoded_probe_length_expected (uint32_t) (NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE - 1)
extern uint8_t test_sig_7[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE];
extern uint8_t test_sig_7_asn_encoded_expected[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE - 1];
extern uint8_t test_sig_7_decoded[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];
extern uint8_t test_sig_7_decoded_expected[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];

// first integer requires no padding, second integer requires padding
#define test_sig_8_asn_encoded_probe_length_expected (uint32_t) (NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE - 1)
extern uint8_t test_sig_8[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE];
extern uint8_t test_sig_8_asn_encoded_expected[NDN_ASN1_ECDSA_SECP256R1_MAX_ENCODED_SIG_SIZE - 1];
extern uint8_t test_sig_8_decoded[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];
extern uint8_t test_sig_8_decoded_expected[NDN_ASN1_ECDSA_SECP256R1_RAW_SIG_SIZE];

#endif // ASN_ENCODE_DECODE_TESTS_DEF_H
