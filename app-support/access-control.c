/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "access-control.h"
#include "../encode/signed-interest.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-key-storage.h"
#include "../security/ndn-lite-random.h"
#include "../security/sec-lib/tinycrypt/tc_ecc_dh.h"
#include "../security/sec-lib/tinycrypt/tc_cbc_mode.h"

static ndn_ac_unfinished_key_t unfinished_key;
static ndn_ac_state_t ac_state;

void
ndn_ac_state_init(const ndn_name_t* self_identity, const ndn_ecc_pub_t* self_pub_key,
                  const ndn_ecc_prv_t* self_prv_key)
{
  for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    ac_state.eks[i] = 0;
    ac_state.dks[i] = 0;
  }
  ac_state.self_identity = *self_identity;
  ac_state.self_pub_key = *self_pub_key;
  ac_state.self_prv_key = *self_prv_key;
}

/************************************************************/
/*  Definition of Encryptor Decryptor APIs                  */
/************************************************************/

int
ndn_ac_prepare_key_request_interest(ndn_encoder_t* encoder,
                                    const ndn_name_t* home_prefix,
                                    const name_component_t* self_identity,
                                    uint32_t ac_key_id, const ndn_ecc_prv_t* prv_key,
                                    uint8_t is_ek)
{
  unfinished_key.key_id = ac_key_id;

  // prepare interest prefix
  // /[home_prefix]/AC/<encryptor_identity>/<parameters_digest>
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  interest.name = *home_prefix;

  name_component_t comp_ac;
  const char* str_ac = "AC";
  name_component_from_string(&comp_ac, str_ac, strlen(str_ac));
  ndn_name_append_component(&interest.name, &comp_ac);
  ndn_name_append_component(&interest.name, self_identity);

  // encode EK type into Parameters
  ndn_encoder_t params_encoder;
  encoder_init(&params_encoder, interest.parameters.value, NDN_INTEREST_PARAMS_BUFFER_SIZE);
  encoder_append_type(&params_encoder, TLV_AC_KEY_TYPE);
  encoder_append_length(&params_encoder, 1);
  if (is_ek > 0)
    encoder_append_byte_value(&params_encoder, NDN_AC_EK); // Encryption Key Request
  else
    encoder_append_byte_value(&params_encoder, NDN_AC_DK); // Decryption Key Request

  // encode KEY ID into Parameters
  encoder_append_type(&params_encoder, TLV_AC_KEY_ID);
  encoder_append_length(&params_encoder, 4);
  encoder_append_uint32_value(&params_encoder, ac_key_id);

  // encode ECDH Pub into Parameters
  unfinished_key.dh_pub.key_size = 64;
  unfinished_key.dh_prv.key_size = 32;
  ndn_ecc_key_make_key(&unfinished_key.dh_pub, &unfinished_key.dh_prv, 
                       NDN_ECDSA_CURVE_SECP256R1, 1234);
  encoder_append_type(&params_encoder, TLV_AC_ECDH_PUB);
  encoder_append_length(&params_encoder, unfinished_key.dh_pub.key_size);
  encoder_append_raw_buffer_value(&params_encoder,
                                  unfinished_key.dh_pub.key_value, unfinished_key.dh_pub.key_size);

  // finish Interest
  interest.parameters.size = params_encoder.offset;
  interest.enable_Parameters = 1;

  // sign Interest
  ndn_name_t self_name = *home_prefix;
  ndn_name_append_component(&self_name, self_identity);
  ndn_signed_interest_tlv_encode_ecdsa_sign(encoder, &interest, &self_name, prv_key);
  return 0;
}

int
ndn_ac_on_ek_response_process(const ndn_data_t* data)
{
  // decode ECDH Pub from content
  ndn_decoder_t decoder;
  uint32_t probe = 0;
  decoder_init(&decoder, data->content_value, data->content_size);
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint8_t ecdh_bytes[64];
  decoder_get_raw_buffer_value(&decoder, ecdh_bytes, sizeof(ecdh_bytes));

  // decode Salt from content
  uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_raw_buffer_value(&decoder, salt, sizeof(salt));

  // ECDH
  uint8_t shared[32];
  ndn_ecc_pub_t ecdh_pubkey;
  ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
  ndn_ecc_key_shared_secret(&ecdh_pubkey, &unfinished_key.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 
                            shared, sizeof(shared));

  // encryption/decryption key generation
  uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];
  ndn_random_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
                  salt, sizeof(salt));

  // decode Lifetime from content
  uint32_t lifetime = 100;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_uint32_value(&decoder, &lifetime);

  // insert ek into the key storage
  ndn_aes_key_t* aes = NULL;
  ndn_key_storage_get_empty_aes_key(&aes);
  if (aes != NULL)
    ndn_aes_key_init(aes, symmetric_key, sizeof(symmetric_key), unfinished_key.key_id);

  // insert ek into the ac state
  for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (ac_state.eks[i] == 0) {
      ac_state.eks[i] = unfinished_key.key_id;
      break;
    }
  }

  return 0;
}

int
ndn_ac_on_dk_response_process(const ndn_data_t* data)
{
  // decode ECDH Pub from content
  ndn_decoder_t decoder;
  uint32_t probe = 0;
  decoder_init(&decoder, data->content_value, data->content_size);
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint8_t ecdh_bytes[64];
  decoder_get_raw_buffer_value(&decoder, ecdh_bytes, sizeof(ecdh_bytes));
  uint8_t shared[32];
  ndn_ecc_pub_t ecdh_pubkey;
  ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
  ndn_ecc_key_shared_secret(&ecdh_pubkey, &unfinished_key.dh_prv, 
                            NDN_ECDSA_CURVE_SECP256R1, shared, sizeof(shared));

  // decode Salt from content
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];
  decoder_get_raw_buffer_value(&decoder, salt, sizeof(salt));

  // decode lifetime from content
  uint32_t lifetime = 100;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_uint32_value(&decoder, &lifetime);

  // temp symmetric key generation
  uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];
  ndn_random_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
                  salt, sizeof(salt));

  // dk decryption
  uint8_t ciphertext[NDN_APPSUPPORT_AC_EDK_SIZE + TC_AES_BLOCK_SIZE] = {0};
  uint8_t plaintext[NDN_APPSUPPORT_AC_EDK_SIZE] = {0};
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_raw_buffer_value(&decoder, ciphertext, sizeof(ciphertext));
  ndn_aes_cbc_decrypt(ciphertext, sizeof(ciphertext),
                      plaintext, sizeof(plaintext), NULL,
                      symmetric_key, sizeof(symmetric_key));

  // insert dk into key storage
  ndn_aes_key_t* aes = NULL;
  ndn_key_storage_get_empty_aes_key(&aes);
  if (aes != NULL)
    ndn_aes_key_init(aes, plaintext, sizeof(plaintext), unfinished_key.key_id);

  // insert dk into the ac state
  for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (ac_state.dks[i] == 0) {
      ac_state.dks[i] = unfinished_key.key_id;
      break;
    }
  }
  return 0;
}

/************************************************************/
/*  Definition of Controller APIs                           */
/************************************************************/

int
ndn_ac_on_interest_process(ndn_data_t* response, const ndn_interest_t* interest)
{
  // decode to determine EK or DK
  ndn_decoder_t decoder;
  decoder_init(&decoder, interest->parameters.value, interest->parameters.size);
  uint32_t probe = 0;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  uint8_t type = 0;
  decoder_get_byte_value(&decoder, &type);

  if (type == NDN_AC_EK) // Encryption Key Request
    return ndn_ac_prepare_ek_response(&decoder, interest, response);

  if (type == NDN_AC_DK) // Decryption Key Request
    return ndn_ac_prepare_dk_response(&decoder, interest, response);

  return NDN_AC_UNRECOGNIZE_KEY_REQUEST;
}

int
ndn_ac_prepare_ek_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
                           ndn_data_t* response)
{
  ndn_ac_unfinished_key_t temp;

  // decode KEY ID
  uint32_t probe = 0;
  decoder_get_type(decoder, &probe);
  decoder_get_length(decoder, &probe);
  decoder_get_uint32_value(decoder, &temp.key_id);

  // TODO: check key policy

  // decode dh pub
  decoder_get_type(decoder, &probe);
  decoder_get_length(decoder, &probe);
  uint8_t ecdh_bytes[64];
  decoder_get_raw_buffer_value(decoder, ecdh_bytes, 64);

  ndn_ecc_key_make_key(&temp.dh_pub, &temp.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 1234);

  uint8_t shared[32];
  ndn_ecc_pub_t ecdh_pubkey;
  ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
  ndn_ecc_key_shared_secret(&ecdh_pubkey, &unfinished_key.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 
                            shared, sizeof(shared));
                            
  // salt generation
  uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];

  // TODO: replace with truly randomness
  uint8_t *personalization = (uint8_t*)"ndn-iot-access-control";
  uint8_t *additional_input = (uint8_t*)"additional-input";
  uint8_t *seed = (uint8_t*)"seed";
  ndn_random_hmacprng(personalization, sizeof(personalization), salt, NDN_APPSUPPORT_AC_SALT_SIZE,
                      seed, sizeof(seed), additional_input, sizeof(additional_input));

  // ek generation
  uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];

  // TODO: update personalization, add, seed with truly randomness
  ndn_random_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
                  salt, sizeof(salt));

  // insert ek into key storage
  ndn_aes_key_t* aes = NULL;
  ndn_key_storage_get_empty_aes_key(&aes);
  if (aes != NULL)
    ndn_aes_key_init(aes, symmetric_key, sizeof(symmetric_key), temp.key_id);

  // insert ek into the ac state
  for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (ac_state.eks[i] == 0) {
      ac_state.eks[i] = temp.key_id;
      break;
    }
  }

  // TODO: lifetime calculation
  uint32_t lifetime = 100;

  // prepare ek Response TLV
  response->name = interest->name;
  ndn_encoder_t encoder;
  encoder_init(&encoder, response->content_value, NDN_CONTENT_BUFFER_SIZE);

  encoder_append_type(&encoder, TLV_AC_ECDH_PUB);
  encoder_append_length(&encoder, 64);
  encoder_append_raw_buffer_value(&encoder, temp.dh_pub.key_value, 64);

  encoder_append_type(&encoder, TLV_AC_SALT);
  encoder_append_length(&encoder, sizeof(salt));
  encoder_append_raw_buffer_value(&encoder, salt, sizeof(salt));

  encoder_append_type(&encoder, TLV_AC_KEY_LIFETIME);
  encoder_append_length(&encoder, 4);
  encoder_append_uint32_value(&encoder, lifetime);

  response->content_size = encoder.offset;
  ndn_metainfo_init(&response->metainfo);
  ndn_metainfo_set_content_type(&response->metainfo, NDN_CONTENT_TYPE_BLOB);
  return 0;
}

int
ndn_ac_prepare_dk_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
                           ndn_data_t* response)
{
  ndn_ac_unfinished_key_t temp;

  // decode KEY ID
  uint32_t probe = 0;
  decoder_get_type(decoder, &probe);
  decoder_get_length(decoder, &probe);
  decoder_get_uint32_value(decoder, &temp.key_id);

  // TODO: check key policy

  // decode dh pub
  decoder_get_type(decoder, &probe);
  decoder_get_length(decoder, &probe);
  uint8_t ecdh_bytes[64];
  decoder_get_raw_buffer_value(decoder, ecdh_bytes, 64);

  ndn_ecc_key_make_key(&temp.dh_pub, &temp.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 1234);

  uint8_t shared[32];
  ndn_ecc_pub_t ecdh_pubkey;
  ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
  ndn_ecc_key_shared_secret(&ecdh_pubkey, &temp.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 
                            shared, sizeof(shared));
  
  // salt generation
  uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];

  // TODO: replace with truly randomness
  uint8_t *personalization = (uint8_t*)"ndn-iot-access-control";
  uint8_t *additional_input = (uint8_t*)"additional-input";
  uint8_t *seed = (uint8_t*)"seed";
  ndn_random_hmacprng(personalization, sizeof(personalization), salt, NDN_APPSUPPORT_AC_SALT_SIZE,
                      seed, sizeof(seed), additional_input, sizeof(additional_input));

  // temp symmetric key generation
  uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];

  // TODO: update personalization, add, seed with truly randomness
  ndn_random_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
                  salt, sizeof(salt));

  // fetch ek by key_id
  ndn_aes_key_t* aes = NULL;
  ndn_key_storage_get_aes_key(temp.key_id, &aes);
  if (aes == NULL)
    return -1;

  // encrypt ek
  uint8_t Encrypted[NDN_APPSUPPORT_AC_EDK_SIZE + TC_AES_BLOCK_SIZE] = {0};
  uint8_t aes_iv[TC_AES_BLOCK_SIZE] = {0};

  // TODO: update personalization, add, seed with truly randomness
  ndn_random_hmacprng(personalization, sizeof(personalization), aes_iv, TC_AES_BLOCK_SIZE,
                      seed, sizeof(seed), additional_input, sizeof(additional_input));
  ndn_aes_cbc_encrypt(aes->key_value, aes->key_size,
                      Encrypted, sizeof(Encrypted), aes_iv,
                      symmetric_key, sizeof(symmetric_key));

  // TODO: lifetime calculation
  uint32_t lifetime = 100;

  // prepare DK Response TLV
  ndn_encoder_t encoder;
  response->name = interest->name;
  encoder_init(&encoder, response->content_value, NDN_CONTENT_BUFFER_SIZE);
  encoder_append_type(&encoder, TLV_AC_ECDH_PUB);
  encoder_append_length(&encoder, 64);
  encoder_append_raw_buffer_value(&encoder, temp.dh_pub.key_value, 64);

  encoder_append_type(&encoder, TLV_AC_SALT);
  encoder_append_length(&encoder, sizeof(salt));
  encoder_append_raw_buffer_value(&encoder, salt, sizeof(salt));

  encoder_append_type(&encoder, TLV_AC_KEY_LIFETIME);
  encoder_append_length(&encoder, 4);
  encoder_append_uint32_value(&encoder, lifetime);

  encoder_append_type(&encoder, TLV_AC_CIPHER_DK);
  encoder_append_length(&encoder, sizeof(Encrypted));
  encoder_append_raw_buffer_value(&encoder, Encrypted, sizeof(Encrypted));

  response->content_size = encoder.offset;
  ndn_metainfo_init(&response->metainfo);
  ndn_metainfo_set_content_type(&response->metainfo, NDN_CONTENT_TYPE_BLOB);

  return 0;
}
