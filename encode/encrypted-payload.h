
/*
 * Copyright (C) Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef NDN_ENCRYPTED_PAYLOAD_H
#define NDN_ENCRYPTED_PAYLOAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void
ndn_gen_encrypted_payload(const uint8_t* input, uint32_t input_size, uint32_t aes_key_id);

void
ndn_parse_encrypted_payload(uint8_t* output, uint32_t* output_size, uint32_t aes_key_id);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCRYPTED_PAYLOAD_H
