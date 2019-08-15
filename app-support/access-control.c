/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "access-control.h"
#include "../encode/signed-interest.h"
#include "../ndn-services.h"
#include "../util/uniform-time.h"
#include "../encode/key-storage.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-rng.h"
#include "../security/ndn-lite-ecc.h"
#include "../security/ndn-lite-hmac.h"

/**
 * The structure to present an unfinished dh key.
 */
typedef struct ac_ongoing_dh {
  bool started;
  /**
   * The locally generated ECC public key.
   */
  ndn_ecc_pub_t dh_pub;
  /**
   * The locally generated ECC private key.
   */
  ndn_ecc_prv_t dh_prv;
} ac_ongoing_dh_t;

typedef struct e_key_state {
  ndn_name_t data_prefix;
  uint32_t key_id;
  ndn_time_ms_t expire_tp;
  uint8_t key_prefix_offset;
} ac_ek_state_t;

typedef struct d_key_state {
  ndn_name_t key_prefix;
  uint32_t key_id;
  ndn_time_ms_t expire_tp;
} ac_dk_state_t;

typedef struct ac_state {
  /**
   * The home prefix component
   */
  const name_component_t* home_prefix;
  ac_ek_state_t ek_state[NDN_APPSUPPORT_AC_KEY_LIST_SIZE];
  ac_dk_state_t dk_state[NDN_APPSUPPORT_AC_KEY_LIST_SIZE];
} ac_state_t;

static ac_ongoing_dh_t m_onging_dh;
static ac_state_t m_ac_state;
static uint8_t ac_buf[4096];

void
ac_init_state(const name_component_t* home_prefix)
{
  m_onging_dh.started = false;
  m_onging_dh.dh_pub.key_id = NDN_SEC_INVALID_KEY_ID;
  m_onging_dh.dh_prv.key_id = NDN_SEC_INVALID_KEY_ID;

  m_ac_state.home_prefix = home_prefix;
  for (int i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    m_ac_state.ek_state[i].data_prefix.components_size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_ac_state.dk_state[i].key_prefix.components_size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_ac_state.ek_state[i].key_id = NDN_SEC_INVALID_KEY_ID;
    m_ac_state.dk_state[i].key_id = NDN_SEC_INVALID_KEY_ID;
  }
}

void
ac_add_data_prefix_need_ek(const ndn_name_t* data_prefix)
{
  for (int i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (m_ac_state.ek_state[i].data_prefix.components_size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      continue;
    }
    if (ndn_name_compare(data_prefix, &m_ac_state.ek_state[i].data_prefix)) {
      // already added
      return;
    }
  }
  for (int i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (m_ac_state.ek_state[i].data_prefix.components_size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      memcpy(&m_ac_state.ek_state[i].data_prefix, data_prefix, sizeof(ndn_name_t));
    }
  }
}

int
ac_get_ek_for_prefix(const ndn_name_t* data_prefix, ndn_aes_key_t* ek)
{
  ndn_time_ms_t now = ndn_time_now_ms();
  for (int i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (ndn_name_compare(data_prefix, &m_ac_state.ek_state[i].data_prefix)) {
      if (m_ac_state.ek_state[i].key_id == NDN_SEC_INVALID_KEY_ID) {
        return NDN_AC_KEY_NOT_OBTAINED;
      }
      else if (m_ac_state.ek_state[i].expire_tp < now) {
        return NDN_AC_KEY_EXPIRED;
      }
      else {
        ndn_key_storage_get_aes_key(m_ac_state.ek_state[i].key_id, &ek);
        return NDN_SUCCESS;
      }
    }
  }
  return NDN_AC_KEY_NOT_FOUND;
}

int
ac_get_dk(const ndn_name_t* key_prefix, ndn_aes_key_t* dk)
{
  ndn_time_ms_t now = ndn_time_now_ms();
  for (int i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (ndn_name_compare(key_prefix, &m_ac_state.dk_state[i].key_prefix)) {
      if (m_ac_state.dk_state[i].key_id == NDN_SEC_INVALID_KEY_ID) {
        return NDN_AC_KEY_NOT_OBTAINED;
      }
      else if (m_ac_state.dk_state[i].expire_tp < now) {
        return NDN_AC_KEY_EXPIRED;
      }
      else {
        ndn_key_storage_get_aes_key(m_ac_state.dk_state[i].key_id, &dk);
        return NDN_SUCCESS;
      }
    }
  }
  return NDN_AC_KEY_NOT_FOUND;
}

void
ac_on_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  uint8_t ek_reply = NDN_SD_AC_EK;
  uint8_t dk_reply = NDN_SD_AC_DK;
  if (memcmp(data.name.components[2].value, &ek_reply, 1)) {
    uint32_t probe = 0;
    // read ecdh pub key from the controller
    decoder_get_type(&decoder, &probe);
    if (probe != TLV_AC_ECDH_PUB) return;
    decoder_get_length(&decoder, &probe);
    uint8_t ecdh_bytes[64];
    decoder_get_raw_buffer_value(&decoder, ecdh_bytes, probe);
    // run ecdh process to obtain shared secret
    uint8_t shared[32];
    ndn_ecc_pub_t ecdh_pubkey;
    ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, probe, NDN_ECDSA_CURVE_SECP256R1, 1);
    ndn_ecc_dh_shared_secret(&ecdh_pubkey, &m_onging_dh.dh_prv, shared, sizeof(shared));
    // decode Salt from content
    uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];
    decoder_get_type(&decoder, &probe);
    if (probe != TLV_AC_SALT) return;
    decoder_get_length(&decoder, &probe);
    decoder_get_raw_buffer_value(&decoder, salt, probe);
    // aes key generation
    uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];
    ndn_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key), salt, sizeof(salt), NULL, 0);
    ndn_aes_key_t aes_key;
    ndn_aes_key_init(&aes_key, symmetric_key, sizeof(symmetric_key), 2);
    // iv read
    uint8_t aes_iv[NDN_AES_BLOCK_SIZE];
    decoder_get_type(&decoder, &probe);
    if (probe != TLV_AC_AES_IV) return;
    decoder_get_length(&decoder, &probe);
    decoder_get_raw_buffer_value(&decoder, aes_iv, NDN_AES_BLOCK_SIZE);
    // read encrypted eks
    ndn_time_ms_t now = ndn_time_now_ms();
    ndn_name_t key_name;

    // read freshness period of the key
    decoder_get_uint32_value(&decoder, &probe);
    uint64_t expire_tp = now + (uint64_t)probe;
    // read keyname
    ndn_name_init(&key_name);
    ndn_name_tlv_decode(&decoder, &key_name);
    // read ciphertext
    decoder_get_type(&decoder, &probe);
    if (probe != TLV_AC_ENCRYPTED_PAYLOAD) return;
    decoder_get_length(&decoder, &probe);
    ndn_aes_cbc_decrypt(decoder.input_value + decoder.offset, probe,
                        ac_buf, probe - NDN_AES_BLOCK_SIZE, aes_iv, &aes_key);
    uint32_t real_len = ndn_aes_parse_unpadding_size(ac_buf, probe - NDN_AES_BLOCK_SIZE);
  }
  else if (memcmp(data.name.components[2].value, &ek_reply, 1)) {

  }
}

void
ac_on_rollover_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
}

void
ac_on_interest_timeout(void* userdata)
{
  // do nothing for now
  (void)userdata;
}

void
ac_start_auto_key_rollover()
{
  ndn_time_ms_t now = ndn_time_now_ms();
  ndn_interest_t interest;
  uint32_t new_key_id = 0;
  ndn_encoder_t encoder;
  for (int i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (m_ac_state.ek_state[i].data_prefix.components_size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
        && m_ac_state.ek_state[i].key_id != NDN_SEC_INVALID_KEY_ID
        && m_ac_state.ek_state[i].expire_tp < now + KEY_ROLLOVER_AHEAD_TIME) {
      ndn_interest_init(&interest);
      for (int i = 0; i < m_ac_state.ek_state[i].key_prefix_offset; i++) {
        ndn_name_append_component(&interest.name, &m_ac_state.ek_state[i].data_prefix.components[i]);
      }
      ndn_name_append_string_component(&interest.name, "EK", strlen("EK"));
      new_key_id = m_ac_state.ek_state[i].key_id + 1;
      if (new_key_id == NDN_SEC_INVALID_KEY_ID) {
        new_key_id++;
      }
      ndn_name_append_bytes_component(&interest.name, (uint8_t*)new_key_id, sizeof(uint32_t));
      // TODO: signature signing
      encoder_init(&encoder, ac_buf, sizeof(ac_buf));
      ndn_interest_tlv_encode(&encoder, &interest);
      ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                     ac_on_rollover_data, ac_on_interest_timeout, NULL);
    }
    if (m_ac_state.dk_state[i].key_prefix.components_size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
        && m_ac_state.dk_state[i].key_id != NDN_SEC_INVALID_KEY_ID
        && m_ac_state.dk_state[i].expire_tp < now + KEY_ROLLOVER_AHEAD_TIME) {
      ndn_interest_init(&interest);
      ndn_name_append_name(&interest.name, &m_ac_state.dk_state[i].key_prefix);
      ndn_name_append_string_component(&interest.name, "DK", strlen("DK"));
      new_key_id = m_ac_state.dk_state[i].key_id + 1;
      if (new_key_id == NDN_SEC_INVALID_KEY_ID) {
        new_key_id++;
      }
      ndn_name_append_bytes_component(&interest.name, (uint8_t*)new_key_id, sizeof(uint32_t));
      // TODO: signature signing
      encoder_init(&encoder, ac_buf, sizeof(ac_buf));
      ndn_interest_tlv_encode(&encoder, &interest);
      ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                     ac_on_rollover_data, ac_on_interest_timeout, NULL);
    }
  }
  ndn_msgqueue_post(NULL, ac_start_auto_key_rollover, NULL, NULL);
}

void
ac_apply_ek()
{
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_name_append_component(&interest.name, m_ac_state.home_prefix);
  uint8_t ac_service = NDN_SD_AC;
  uint8_t ac_ek_service = NDN_SD_AC_EK;
  ndn_name_append_bytes_component(&interest.name, &ac_service, 1);
  ndn_name_append_bytes_component(&interest.name, &ac_ek_service, 1);

  ndn_encoder_t encoder;
  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  // create ecc key pair
  ndn_ecc_make_key(&m_onging_dh.dh_pub, &m_onging_dh.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 1);
  m_onging_dh.started = true;
  // append an ECDH public key into application parameter
  encoder_append_type(&encoder, TLV_AC_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(&m_onging_dh.dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(&m_onging_dh.dh_pub),
                                  ndn_ecc_get_pub_key_size(&m_onging_dh.dh_pub));
  // append production prefixes into application parameter
  for (int i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
    if (m_ac_state.ek_state[i].data_prefix.components_size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
        && m_ac_state.ek_state[i].key_id == NDN_SEC_INVALID_KEY_ID) {
      ndn_name_tlv_encode(&encoder, &m_ac_state.ek_state[i].data_prefix);
    }
  }
  ndn_interest_set_Parameters(&interest, encoder.output_value, encoder.offset);

  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                 ac_on_data, ac_on_interest_timeout, NULL);
}

void
ac_apply_dk(const ndn_name_t* key_name, bool one_time)
{
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_name_append_component(&interest.name, m_ac_state.home_prefix);
  uint8_t ac_service = NDN_SD_AC;
  uint8_t ac_ek_service = NDN_SD_AC_DK;
  ndn_name_append_bytes_component(&interest.name, &ac_service, 1);
  ndn_name_append_bytes_component(&interest.name, &ac_ek_service, 1);

  ndn_encoder_t encoder;
  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  // create ecc key pair
  ndn_ecc_make_key(&m_onging_dh.dh_pub, &m_onging_dh.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 1);
  m_onging_dh.started = true;
  // append an ECDH public key into application parameter
  encoder_append_type(&encoder, TLV_AC_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(&m_onging_dh.dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(&m_onging_dh.dh_pub),
                                  ndn_ecc_get_pub_key_size(&m_onging_dh.dh_pub));
  // append the bool indicating whether a long-term access right
  if (one_time) {
    encoder_append_byte_value(&encoder, 1);
  }
  else {
    encoder_append_byte_value(&encoder, 0);
  }
  // append desired key name
  ndn_name_tlv_encode(&encoder, key_name);
  ndn_interest_set_Parameters(&interest, encoder.output_value, encoder.offset);

  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                 ac_on_data, ac_on_interest_timeout, NULL);
}

// static ndn_ac_unfinished_key_t unfinished_key;
// static ndn_ac_state_t ac_state;

// void
// ndn_ac_state_init(const ndn_name_t* self_identity, const ndn_ecc_pub_t* self_pub_key,
//                   const ndn_ecc_prv_t* self_prv_key)
// {
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
//     ac_state.eks[i] = 0;
//     ac_state.dks[i] = 0;
//   }
//   ac_state.self_identity = *self_identity;
//   ac_state.self_pub_key = *self_pub_key;
//   ac_state.self_prv_key = *self_prv_key;
// }

// /************************************************************/
// /*  Definition of Encryptor Decryptor APIs                  */
// /************************************************************/

// int
// ndn_ac_prepare_key_request_interest(ndn_encoder_t* encoder,
//                                     const ndn_name_t* home_prefix,
//                                     const name_component_t* self_identity,
//                                     uint32_t ac_key_id, const ndn_ecc_prv_t* prv_key,
//                                     uint8_t is_ek)
// {
//   unfinished_key.key_id = ac_key_id;

//   // prepare interest prefix
//   // /[home_prefix]/AC/<encryptor_identity>/<parameters_digest>
//   ndn_interest_t interest;
//   ndn_interest_init(&interest);
//   memcpy(&interest.name, home_prefix, sizeof(ndn_name_t));

//   // append AC component
//   name_component_t comp_ac;
//   const char* str_ac = "AC";
//   name_component_from_string(&comp_ac, str_ac, strlen(str_ac));
//   ndn_name_append_component(&interest.name, &comp_ac);
//   ndn_name_append_component(&interest.name, self_identity);

//   // encode EK type into Parameters
//   ndn_encoder_t params_encoder;
//   encoder_init(&params_encoder, interest.parameters.value, NDN_INTEREST_PARAMS_BUFFER_SIZE);
//   encoder_append_type(&params_encoder, TLV_AC_KEY_TYPE);
//   encoder_append_length(&params_encoder, 1);
//   if (is_ek > 0)
//     encoder_append_byte_value(&params_encoder, NDN_AC_EK); // Encryption Key Request
//   else
//     encoder_append_byte_value(&params_encoder, NDN_AC_DK); // Decryption Key Request

//   // encode KEY ID into Parameters
//   encoder_append_type(&params_encoder, TLV_AC_KEY_ID);
//   encoder_append_length(&params_encoder, 4);
//   encoder_append_uint32_value(&params_encoder, ac_key_id);

//   // encode ECDH Pub into Parameters
//   ndn_ecc_make_key(&unfinished_key.dh_pub, &unfinished_key.dh_prv,
//                    NDN_ECDSA_CURVE_SECP256R1, 1234);
//   encoder_append_type(&params_encoder, TLV_AC_ECDH_PUB);
//   encoder_append_length(&params_encoder, ndn_ecc_get_pub_key_size(&unfinished_key.dh_pub));
//   encoder_append_raw_buffer_value(&params_encoder,
//                                   ndn_ecc_get_pub_key_value(&unfinished_key.dh_pub),
//                                   ndn_ecc_get_pub_key_size(&unfinished_key.dh_pub));

//   // finish Interest
//   interest.parameters.size = params_encoder.offset;
//   BIT_SET(interest.flags, 6);

//   // sign Interest
//   ndn_name_t self_name;
//   memcpy(&self_name, home_prefix, sizeof(ndn_name_t));
//   ndn_name_append_component(&self_name, self_identity);
//   ndn_signed_interest_ecdsa_sign(&interest, &self_name, prv_key);
//   ndn_interest_tlv_encode(encoder, &interest);
//   return 0;
// }

// int
// ndn_ac_on_ek_response_process(const ndn_data_t* data)
// {
//   // decode ECDH Pub from content
//   ndn_decoder_t decoder;
//   uint32_t probe = 0;
//   decoder_init(&decoder, data->content_value, data->content_size);
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   uint8_t ecdh_bytes[64];
//   decoder_get_raw_buffer_value(&decoder, ecdh_bytes, sizeof(ecdh_bytes));

//   // decode Salt from content
//   uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   decoder_get_raw_buffer_value(&decoder, salt, sizeof(salt));

//   // ECDH
//   uint8_t shared[32];
//   ndn_ecc_pub_t ecdh_pubkey;
//   ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
//   ndn_ecc_dh_shared_secret(&ecdh_pubkey, &unfinished_key.dh_prv, NDN_ECDSA_CURVE_SECP256R1,
//                            shared, sizeof(shared));

//   // encryption/decryption key generation
//   uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];
//   ndn_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
//            salt, sizeof(salt));

//   // decode Lifetime from content
//   uint32_t lifetime = 100;
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   decoder_get_uint32_value(&decoder, &lifetime);

//   // insert ek into the key storage
//   ndn_aes_key_t* aes = NULL;
//   ndn_key_storage_get_empty_aes_key(&aes);
//   if (aes != NULL)
//     ndn_aes_key_init(aes, symmetric_key, sizeof(symmetric_key), unfinished_key.key_id);

//   // insert ek into the ac state
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
//     if (ac_state.eks[i] == 0) {
//       ac_state.eks[i] = unfinished_key.key_id;
//       break;
//     }
//   }

//   return 0;
// }

// int
// ndn_ac_on_dk_response_process(const ndn_data_t* data)
// {
//   // decode ECDH Pub from content
//   ndn_decoder_t decoder;
//   uint32_t probe = 0;
//   decoder_init(&decoder, data->content_value, data->content_size);
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   uint8_t ecdh_bytes[64];
//   decoder_get_raw_buffer_value(&decoder, ecdh_bytes, sizeof(ecdh_bytes));
//   uint8_t shared[32];
//   ndn_ecc_pub_t ecdh_pubkey;
//   ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
//   ndn_ecc_dh_shared_secret(&ecdh_pubkey, &unfinished_key.dh_prv,
//                            NDN_ECDSA_CURVE_SECP256R1, shared, sizeof(shared));

//   // decode Salt from content
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];
//   decoder_get_raw_buffer_value(&decoder, salt, sizeof(salt));

//   // decode lifetime from content
//   uint32_t lifetime = 100;
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   decoder_get_uint32_value(&decoder, &lifetime);

//   // temp symmetric key generation
//   uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];
//   ndn_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
//            salt, sizeof(salt));
//   ndn_aes_key_t sym_aes_key;
//   ndn_aes_key_init(&sym_aes_key, symmetric_key, sizeof(symmetric_key), 1);

//   // dk decryption
//   uint8_t ciphertext[ndn_aes_probe_padding_size(NDN_APPSUPPORT_AC_EDK_SIZE) +
//                      NDN_AES_BLOCK_SIZE];
//   uint8_t plaintext[NDN_APPSUPPORT_AC_EDK_SIZE];
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   decoder_get_raw_buffer_value(&decoder, ciphertext, sizeof(ciphertext));
//   ndn_aes_cbc_decrypt(ciphertext, sizeof(ciphertext), plaintext,
//                       sizeof(plaintext), NULL, &sym_aes_key);

//   // insert dk into key storage
//   ndn_aes_key_t* aes = NULL;
//   ndn_key_storage_get_empty_aes_key(&aes);
//   if (aes != NULL)
//     ndn_aes_key_init(aes, plaintext, sizeof(plaintext), unfinished_key.key_id);

//   // insert dk into the ac state
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
//     if (ac_state.dks[i] == 0) {
//       ac_state.dks[i] = unfinished_key.key_id;
//       break;
//     }
//   }
//   return 0;
// }

// /************************************************************/
// /*  Definition of Controller APIs                           */
// /************************************************************/

// int
// ndn_ac_on_interest_process(ndn_data_t* response, const ndn_interest_t* interest)
// {
//   // decode to determine EK or DK
//   ndn_decoder_t decoder;
//   decoder_init(&decoder, interest->parameters.value, interest->parameters.size);
//   uint32_t probe = 0;
//   decoder_get_type(&decoder, &probe);
//   decoder_get_length(&decoder, &probe);
//   uint8_t type = 0;
//   decoder_get_byte_value(&decoder, &type);

//   if (type == NDN_AC_EK) // Encryption Key Request
//     return ndn_ac_prepare_ek_response(&decoder, interest, response);

//   if (type == NDN_AC_DK) // Decryption Key Request
//     return ndn_ac_prepare_dk_response(&decoder, interest, response);

//   return NDN_AC_UNRECOGNIZED_KEY_REQUEST;
// }

// int
// ndn_ac_prepare_ek_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
//                            ndn_data_t* response)
// {
//   ndn_ac_unfinished_key_t temp;

//   // decode KEY ID
//   uint32_t probe = 0;
//   decoder_get_type(decoder, &probe);
//   decoder_get_length(decoder, &probe);
//   decoder_get_uint32_value(decoder, &temp.key_id);

//   // TODO: check key policy

//   // decode dh pub
//   decoder_get_type(decoder, &probe);
//   decoder_get_length(decoder, &probe);
//   uint8_t ecdh_bytes[64];
//   decoder_get_raw_buffer_value(decoder, ecdh_bytes, 64);
//   ndn_ecc_make_key(&temp.dh_pub, &temp.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 1234);

//   uint8_t shared[32];
//   ndn_ecc_pub_t ecdh_pubkey;
//   ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
//   ndn_ecc_dh_shared_secret(&ecdh_pubkey, &unfinished_key.dh_prv, NDN_ECDSA_CURVE_SECP256R1,
//                            shared, sizeof(shared));

//   // salt generation
//   uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];

//   // TODO: replace with truly randomness
//   uint8_t *personalization = (uint8_t*)"ndn-iot-access-control";
//   uint8_t *additional_input = (uint8_t*)"additional-input";
//   uint8_t *seed = (uint8_t*)"seed";
//   ndn_hmacprng(personalization, sizeof(personalization), salt, NDN_APPSUPPORT_AC_SALT_SIZE,
//                seed, sizeof(seed), additional_input, sizeof(additional_input));

//   // ek generation
//   uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];

//   // TODO: update personalization, add, seed with truly randomness
//   ndn_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
//            salt, sizeof(salt));

//   // insert ek into key storage
//   ndn_aes_key_t* aes = NULL;
//   ndn_key_storage_get_empty_aes_key(&aes);
//   if (aes != NULL)
//     ndn_aes_key_init(aes, symmetric_key, sizeof(symmetric_key), temp.key_id);

//   // insert ek into the ac state
//   for (uint8_t i = 0; i < NDN_APPSUPPORT_AC_KEY_LIST_SIZE; i++) {
//     if (ac_state.eks[i] == 0) {
//       ac_state.eks[i] = temp.key_id;
//       break;
//     }
//   }

//   // TODO: lifetime calculation
//   uint32_t lifetime = 100;

//   // prepare ek Response TLV
//   memcpy(&response->name, &interest->name, sizeof(ndn_name_t));
//   response->name = interest->name;
//   ndn_encoder_t encoder;
//   encoder_init(&encoder, response->content_value, NDN_CONTENT_BUFFER_SIZE);

//   encoder_append_type(&encoder, TLV_AC_ECDH_PUB);
//   encoder_append_length(&encoder, 64);
//   encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(&temp.dh_pub), 64);

//   encoder_append_type(&encoder, TLV_AC_SALT);
//   encoder_append_length(&encoder, sizeof(salt));
//   encoder_append_raw_buffer_value(&encoder, salt, sizeof(salt));

//   encoder_append_type(&encoder, TLV_AC_KEY_LIFETIME);
//   encoder_append_length(&encoder, 4);
//   encoder_append_uint32_value(&encoder, lifetime);

//   response->content_size = encoder.offset;
//   ndn_metainfo_init(&response->metainfo);
//   ndn_metainfo_set_content_type(&response->metainfo, NDN_CONTENT_TYPE_BLOB);
//   return 0;
// }

// int
// ndn_ac_prepare_dk_response(ndn_decoder_t* decoder, const ndn_interest_t* interest,
//                            ndn_data_t* response)
// {
//   ndn_ac_unfinished_key_t temp;

//   // decode KEY ID
//   uint32_t probe = 0;
//   decoder_get_type(decoder, &probe);
//   decoder_get_length(decoder, &probe);
//   decoder_get_uint32_value(decoder, &temp.key_id);

//   // TODO: check key policy

//   // decode dh pub
//   decoder_get_type(decoder, &probe);
//   decoder_get_length(decoder, &probe);
//   uint8_t ecdh_bytes[64];
//   decoder_get_raw_buffer_value(decoder, ecdh_bytes, 64);

//   ndn_ecc_make_key(&temp.dh_pub, &temp.dh_prv, NDN_ECDSA_CURVE_SECP256R1, 1234);

//   uint8_t shared[32];
//   ndn_ecc_pub_t ecdh_pubkey;
//   ndn_ecc_pub_init(&ecdh_pubkey, ecdh_bytes, sizeof(ecdh_bytes), NDN_ECDSA_CURVE_SECP256R1, 2345);
//   ndn_ecc_dh_shared_secret(&ecdh_pubkey, &temp.dh_prv, NDN_ECDSA_CURVE_SECP256R1,
//                            shared, sizeof(shared));

//   // salt generation
//   uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];

//   // TODO: replace with truly randomness
//   uint8_t *personalization = (uint8_t*)"ndn-iot-access-control";
//   uint8_t *additional_input = (uint8_t*)"additional-input";
//   uint8_t *seed = (uint8_t*)"seed";
//   ndn_hmacprng(personalization, sizeof(personalization), salt, NDN_APPSUPPORT_AC_SALT_SIZE,
//                seed, sizeof(seed), additional_input, sizeof(additional_input));

//   // temp symmetric key generation
//   uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];

//   // TODO: update personalization, add, seed with truly randomness
//   ndn_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
//            salt, sizeof(salt));
//   ndn_aes_key_t sym_key;
//   ndn_aes_key_init(&sym_key, symmetric_key, sizeof(symmetric_key), 2);

//   // fetch ek by key_id
//   ndn_aes_key_t* aes = NULL;
//   ndn_key_storage_get_aes_key(temp.key_id, &aes);
//   if (aes == NULL)
//     return -1;

//   // encrypt ek
//   uint8_t Encrypted[ndn_aes_probe_padding_size(NDN_APPSUPPORT_AC_EDK_SIZE) +
//                     NDN_AES_BLOCK_SIZE];
//   uint8_t aes_iv[NDN_AES_BLOCK_SIZE];

//   // TODO: update personalization, add, seed with truly randomness
//   ndn_hmacprng(personalization, sizeof(personalization), aes_iv, NDN_AES_BLOCK_SIZE,
//                       seed, sizeof(seed), additional_input, sizeof(additional_input));
//   ndn_aes_cbc_encrypt(ndn_aes_get_key_value(aes), ndn_aes_get_key_size(aes),
//                       Encrypted, sizeof(Encrypted), aes_iv, &sym_key);

//   // TODO: lifetime calculation
//   uint32_t lifetime = 100;

//   // prepare DK Response TLV
//   ndn_encoder_t encoder;
//   memcpy(&response->name, &interest->name, sizeof(ndn_name_t));
//   encoder_init(&encoder, response->content_value, NDN_CONTENT_BUFFER_SIZE);
//   encoder_append_type(&encoder, TLV_AC_ECDH_PUB);
//   encoder_append_length(&encoder, 64);
//   encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(&temp.dh_pub), 64);

//   encoder_append_type(&encoder, TLV_AC_SALT);
//   encoder_append_length(&encoder, sizeof(salt));
//   encoder_append_raw_buffer_value(&encoder, salt, sizeof(salt));

//   encoder_append_type(&encoder, TLV_AC_KEY_LIFETIME);
//   encoder_append_length(&encoder, 4);
//   encoder_append_uint32_value(&encoder, lifetime);

//   encoder_append_type(&encoder, TLV_AC_CIPHER_DK);
//   encoder_append_length(&encoder, sizeof(Encrypted));
//   encoder_append_raw_buffer_value(&encoder, Encrypted, sizeof(Encrypted));

//   response->content_size = encoder.offset;
//   ndn_metainfo_init(&response->metainfo);
//   ndn_metainfo_set_content_type(&response->metainfo, NDN_CONTENT_TYPE_BLOB);

//   return 0;
// }
