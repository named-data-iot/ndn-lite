/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ENCODING_DATA_H
#define NDN_ENCODING_DATA_H

#include "signature.h"
#include "metainfo.h"
#include "../security/ndn-lite-hmac.h"
#include "../security/ndn-lite-ecc.h"
#include "../security/ndn-lite-sha.h"
#include "../security/ndn-lite-aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to represent an NDN Data packet
 * The best practice of using ndn_data_t is to first declare a ndn_data_t object
 * and init each of its component to save memory
 */
typedef struct ndn_data {
  /**
   * Data Name Value (not including T and L)
   */
  ndn_name_t name;
  /**
   * Data MetaInfo Value (not including T and L)
   */
  ndn_metainfo_t metainfo;
  /**
   * Data Content Value (not including T and L)
   */
  uint8_t content_value[NDN_CONTENT_BUFFER_SIZE];
  /**
   * Data MetaInfo Content Value Size
   */
  uint32_t content_size;
  /**
   * Data Signature.
   * This attribute should not be manually modified.
   * Use ndn_data_tlv_encode_*_sign functions to generate signature.
   */
  ndn_signature_t signature;
} ndn_data_t;


/**
 * Init an Data packet.
 * This function should be invoked
 * whenever a new ndn_data_t is created.
 * @param data. Output. The Data to be inited.
 */
static inline void
ndn_data_init(ndn_data_t* data)
{
  ndn_metainfo_init(&data->metainfo);
}

int
ndn_data_tlv_encode(ndn_encoder_t* encoder, ndn_data_t* data);

/**
 * Use Digest (SHA256) to sign the Data and encode the Data into wire format.
 * This function will automatically set signature info and signature value.
 * @param encoder Output. The encoder to keep the encoded Data.
 *        The encoder should be inited to proper output buffer.
 * @param data Input. The data to be encoded.
 * @return 0 if there is no error.
 */
int
ndn_data_tlv_encode_digest_sign(ndn_encoder_t* encoder, ndn_data_t* data);

/**
 * Use ECDSA Algorithm to sign the Data and encode the Data into wire format.
 * This function will automatically set signature info and signature value.
 * @param encoder. Output. The encoder to keep the encoded Data.
 *        The encoder should be inited to proper output buffer.
 * @param data. Input. The data to be encoded.
 * @param producer_identity. Input. The producer's identity name.
 * @param prv_key. Input. The private ECC key used to generate the signature.
 * @return 0 if there is no error.
 */
int
ndn_data_tlv_encode_ecdsa_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                               const ndn_name_t* producer_identity, const ndn_ecc_prv_t* prv_key);

/**
 * Use HMAC Algorithm to sign the Data and encode the Data into wire format.
 * This function will automatically set signature info and signature value.
 * @param encoder. Output. The encoder to keep the encoded Data.
 *        The encoder should be inited to proper output buffer.
 * @param data. Input. The data to be encoded.
 * @param producer_identity. Input. The producer's identity name.
 * @param prv_key. Input. The HMAC key used to generate the signature.
 * @return 0 if there is no error.
 */
int
ndn_data_tlv_encode_hmac_sign(ndn_encoder_t* encoder, ndn_data_t* data,
                              const ndn_name_t* producer_identity, const ndn_hmac_key_t* hmac_key);

/**
 * Simply decode the encoded Data into a ndn_data_t without signature verification.
 * @param data. Output. The data to which the wired block will be decoded.
 * @param block_value. Input. The wire format Data buffer.
 * @param block_size. Input. The size of the wire format Data buffer.
 * @return 0 if there is no error.
 */
int
ndn_data_tlv_decode_no_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                              uint32_t* be_signed_start, uint32_t* be_signed_end);

/**
 * Decode the encoded Data into a ndn_data_t and verify the Digest (SHA256) signature.
 * @param data. Output. The data to which the wired block will be decoded.
 * @param block_value. Input. The wire format Data buffer.
 * @param block_size. Input. The size of the wire format Data buffer.
 * @return 0 if there is no error and the signature is valid.
 */
int
ndn_data_tlv_decode_digest_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size);

/**
 * Decode the encoded Data into a ndn_data_t and verify the ECDSA signature.
 * @param data. Output. The data to which the wired block will be decoded.
 * @param block_value. Input. The wire format Data buffer.
 * @param block_size. Input. The size of the wire format Data buffer.
 * @param pub_key. Input. The ECC public key used to verify the Data signature.
 * @return 0 if there is no error and the signature is valid.
 */
int
ndn_data_tlv_decode_ecdsa_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                 const ndn_ecc_pub_t* pub_key);

/**
 * Decode the encoded Data into a ndn_data_t and verify the HMAC signature.
 * @param data. Output. The data to which the wired block will be decoded.
 * @param block_value. Input. The wire format Data buffer.
 * @param block_size. Input. The size of the wire format Data buffer.
 * @param hmac_key. Input. The HMAC key used to verify the Data signature.
 * @return 0 if there is no error and the signature is valid.
 */
int
ndn_data_tlv_decode_hmac_verify(ndn_data_t* data, const uint8_t* block_value, uint32_t block_size,
                                const ndn_hmac_key_t* hmac_key);

/**
 * Set the Data content.
 * @param data. Output. The data whose content will be set.
 * @param content_value. Input. The content buffer (Content Value only, no T(type) and L(length)).
 * @param content_size. Input. The size of the content buffer.
 * @return 0 if there is no error.
 */
static inline int
ndn_data_set_content(ndn_data_t* data, uint8_t* content_value, uint32_t content_size)
{
  if (content_size <= NDN_CONTENT_BUFFER_SIZE) {
    memcpy(data->content_value, content_value, content_size);
    data->content_size = content_size;
    return 0;
  }else{
    return NDN_OVERSIZE;
  }
}

/**
 * Set the Data content with the encrypted content.
 * The content payload will be encrypted with AES CBC without padding.
 * @param data. Output. The data whose content will be set.
 * @param content_value. Input. The content buffer (Content Value only, no T(type) and L(length)).
 * @param content_size. Input. The size of the content buffer.
 * @param key_name. Input. The encryption key name.
 * @return 0 if there is no error.
 */
int
ndn_data_set_encrypted_content(ndn_data_t* data, const uint8_t* content_value, uint32_t content_size,
                               const ndn_name_t* key_name, const uint8_t* iv, uint32_t iv_size);

/**
 * Parse the Data encrypted content and get the decrypted content.
 * The content payload will be decrypted with AES CBC without padding.
 * @param data. Input. The data whose content will be set.
 * @param payload_value. Output. The decrypted content buffer.
 * @param payload_used_size. Output. The size of the decrypted content buffer.
 * @param key_id. Output. The encryption key name.
 * @param aes_iv. Output. The IV used for AES decryption.
 * @param key. Input. The AES key used for AES decryption.
 * @return 0 if there is no error.
 */
int
ndn_data_parse_encrypted_content(const ndn_data_t* data, uint8_t* payload_value, uint32_t* payload_used_size,
                                 ndn_name_t* key_name);

#ifdef __cplusplus
}
#endif

#endif // NDN_ENCODING_DATA_H
