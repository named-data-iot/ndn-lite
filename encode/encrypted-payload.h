/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCRYPTED_PAYLOAD_H
#define NDN_ENCRYPTED_PAYLOAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Encrypted Payload TLV Format
 * T=TLV_AC_AES_IV L V=Bytes: IV for AES encryption
 * T=TLV_AC_ENCRYPTED_PAYLOAD L V=Bytes: Encrypted Content
 */

int
ndn_probe_encrypted_payload_length(uint32_t input_size);

/** Generate a TLV encoded ciphertext from plaintext.
 *
 * @param input. Input. The plaintext buffer.
 * @param input_size. Input. The size of plaintext buffer.
 * @param output. Output. The buffer to keep the TLV encoded ciphertext.
 * @param used_size. Output. The number of bytes used by the two TLV blocks.
 * @param aes_key_id. Input. The key id used to fetch a key from ndn-lite key storage.
 * @param iv. Input. IV. Can be NULL. When IV is null, the function will randomly generate it.
 * @param iv_size. Input. IV's size. Can be zero.
 */
int
ndn_gen_encrypted_payload(const uint8_t* input, uint32_t input_size, uint8_t* output, uint32_t* used_size,
                          uint32_t aes_key_id, const uint8_t* iv, uint32_t iv_size);

/** Decrypt a TLV encoded ciphertext to plaintext.
 *
 * @param input. Input. The TLV encoded ciphertext buffer.
 * @param input_size. Input. The size of TLV encoded ciphertext buffer.
 * @param output. Output. The buffer to keep the decrypted plaintext
 * @param output_size. Output. The size of decrypted plaintext.
 * @param aes_key_id. Input. The key id used to fetch a key from ndn-lite key storage.
 */
int
ndn_parse_encrypted_payload(const uint8_t* input, uint32_t input_size,
                            uint8_t* output, uint32_t* output_size, uint32_t aes_key_id);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCRYPTED_PAYLOAD_H
