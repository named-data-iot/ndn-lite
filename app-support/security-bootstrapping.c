/*
 * Copyright (C) 2018-2019 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#include "security-bootstrapping.h"
#include "service-discovery.h"
#include "../encode/interest.h"
#include "../encode/signed-interest.h"
#include "../encode/data.h"
#include "../encode/key-storage.h"
#include "../ndn-error-code.h"
#include "../util/uniform-time.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-sha.h"

typedef struct ndn_sec_boot_state {
  ndn_face_intf_t* face;
  const uint8_t* service_list;
  size_t list_size;
  const char* device_identifier;
  size_t identifier_size;
  uint8_t trust_anchor_sha[NDN_SEC_SHA256_HASH_SIZE];
  ndn_ecc_pub_t controller_dh_pub;
  const ndn_ecc_prv_t* pre_installed_ecc_key;
  const ndn_hmac_key_t* pre_shared_hmac_key;
} ndn_sec_boot_state_t;

static uint8_t sec_boot_buf[4096];
static ndn_sec_boot_state_t m_sec_boot_state;
static const uint32_t SEC_BOOT_DH_KEY_ID = 10001;
static const uint32_t SEC_BOOT_AES_KEY_ID = 10002;

// some common rules: 1. keep keys in key_storage 2. delete the key from key storage if its not used any longer

int sec_boot_send_sign_on_interest();
int sec_boot_send_cert_interest();

void
sec_boot_after_bootstrapping()
{
  ndn_key_storage_delete_aes_key(SEC_BOOT_AES_KEY_ID);
  ndn_key_storage_delete_ecc_key(SEC_BOOT_DH_KEY_ID);
}

void
on_sec_boot_sign_on_interest_timeout (void* userdata)
{
  // do nothing for now
  (void)userdata;
  printf("\nSEC BOOTSTRAPPING sign on interest timeout\n");
  sec_boot_send_sign_on_interest();
}

void
on_sec_boot_cert_interest_timeout (void* userdata)
{
  // do nothing for now
  (void)userdata;
  printf("\nSEC BOOTSTRAPPING cert timeout\n");
  sec_boot_send_cert_interest();
}

void
on_cert_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_hmac_verify(&data, raw_data, data_size, m_sec_boot_state.pre_shared_hmac_key) != NDN_SUCCESS) {
    printf("Decoding failed.\n");
    return;
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  // parse content
  // format: self certificate, encrypted key
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  // self cert certificate
  uint32_t probe = 0;
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_Data) return;
  decoder_get_length(&decoder, &probe);
  ndn_data_t self_cert;
  if (ndn_data_tlv_decode_no_verify(&self_cert, data.content_value, encoder_probe_block_size(TLV_Data, probe), NULL, NULL) != NDN_SUCCESS) {
    return;
  }
  // iv
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_AES_IV) return;
  decoder_get_length(&decoder, &probe);
  uint8_t aes_iv[NDN_SEC_AES_IV_LENGTH];
  decoder_get_raw_buffer_value(&decoder, aes_iv, NDN_SEC_AES_IV_LENGTH);
  // encrypted private key
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_ENCRYPTED_PAYLOAD) return;
  decoder_get_length(&decoder, &probe);
  uint8_t plaintext[1024];
  ndn_aes_key_t* sym_aes_key = NULL;
  ndn_key_storage_get_aes_key(SEC_BOOT_AES_KEY_ID, &sym_aes_key);
  ndn_aes_cbc_decrypt(decoder.input_value + decoder.offset, probe,
                      plaintext, probe - NDN_AES_BLOCK_SIZE, aes_iv, sym_aes_key);
  // set key storage
  ndn_ecc_prv_t self_prv;
  uint32_t keyid = *(uint32_t*)&self_cert.name.components[self_cert.name.components_size - 3].value;
  ndn_ecc_prv_init(&self_prv, plaintext, 64, NDN_ECDSA_CURVE_SECP256R1, keyid);
  ndn_key_storage_set_self_identity(&self_cert, &self_prv);
  // finish the bootstrapping process
  sec_boot_after_bootstrapping();
}

int
sec_boot_send_cert_interest()
{
  // generate the cert interest (2nd interest)
  int ret = 0;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_key_storage_t* key_storage = ndn_key_storage_get_instance();
  ndn_name_append_component(&interest.name, &key_storage->trust_anchor.name.components[0]);
  ndn_name_append_string_component(&interest.name, "cert", strlen("cert"));
  // set params
  // format: name component, N2, sha2 of trust anchor, N1
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  // identifier name component
  name_component_t device_identifier_comp;
  name_component_from_string(&device_identifier_comp, m_sec_boot_state.device_identifier,
                             m_sec_boot_state.identifier_size);
  name_component_tlv_encode(&encoder, &device_identifier_comp);
  // append the ecdh pub key, N2
  encoder_append_type(&encoder, TLV_SEC_BOOT_N2_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(&m_sec_boot_state.controller_dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(&m_sec_boot_state.controller_dh_pub), 
                                  ndn_ecc_get_pub_key_size(&m_sec_boot_state.controller_dh_pub));
  // append sha256 of the trust anchor
  encoder_append_type(&encoder, TLV_SEC_BOOT_ANCHOR_DIGEST);
  encoder_append_length(&encoder, NDN_SEC_SHA256_HASH_SIZE);
  encoder_append_raw_buffer_value(&encoder, m_sec_boot_state.trust_anchor_sha, NDN_SEC_SHA256_HASH_SIZE);
  // append the ecdh pub key, N1
  ndn_ecc_pub_t* self_dh_pub = NULL;
  ndn_key_storage_get_ecc_pub_key(SEC_BOOT_DH_KEY_ID, &self_dh_pub);
  encoder_append_type(&encoder, TLV_SEC_BOOT_N1_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(self_dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(self_dh_pub),
                                  ndn_ecc_get_pub_key_size(self_dh_pub));
  // set parameter
  ndn_interest_set_Parameters(&interest, encoder.output_value, encoder.offset);
  // set must be fresh
  ndn_interest_set_MustBeFresh(&interest,true);
  // sign the interest
  ndn_signed_interest_ecdsa_sign(&interest, &interest.name, m_sec_boot_state.pre_installed_ecc_key);
  // send it out
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                       on_cert_data, on_sec_boot_cert_interest_timeout, NULL);
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send SEC BOOT cert Interest packet with name: \n");
  ndn_name_print(&interest.name);
  return NDN_SUCCESS;
}

void
on_sign_on_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_hmac_verify(&data, raw_data, data_size, m_sec_boot_state.pre_shared_hmac_key) != NDN_SUCCESS) {
    printf("Decoding failed.\n");
    return;
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_time_ms_t now = ndn_time_now_ms();
  uint32_t probe = 0;
  // parse content
  // format: a data packet, ecdh pub, salt
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  // trust anchor certificate
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_Data) return;
  decoder_get_length(&decoder, &probe);
  decoder.offset += probe;
  // calculate the sha256 digest of the trust anchor
  ndn_sha256(decoder.input_value, encoder_probe_block_size(TLV_Data, probe),
             m_sec_boot_state.trust_anchor_sha);
  ndn_data_t trust_anchor_cert;
  if (ndn_data_tlv_decode_no_verify(&trust_anchor_cert, data.content_value, encoder_probe_block_size(TLV_Data, probe), NULL, NULL) != NDN_SUCCESS) {
    return;
  }
  // key storage set trust anchor
  ndn_key_storage_set_trust_anchor(&trust_anchor_cert);
  // parse ecdh pub key, N2
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_SEC_BOOT_N2_ECDH_PUB) return;
  decoder_get_length(&decoder, &probe);
  uint8_t dh_pub_buf[100];
  decoder_get_raw_buffer_value(&decoder, dh_pub_buf, probe);
  ndn_ecc_pub_init(&m_sec_boot_state.controller_dh_pub, dh_pub_buf, probe, NDN_ECDSA_CURVE_SECP256R1, 1);
  ndn_ecc_prv_t* self_prv_key = NULL;
  ndn_key_storage_get_ecc_prv_key(SEC_BOOT_DH_KEY_ID, &self_prv_key);
  // get shared secret using DH process
  uint8_t shared[32];
  ndn_ecc_dh_shared_secret(&m_sec_boot_state.controller_dh_pub, self_prv_key, shared, sizeof(shared));
  // decode salt from the replied data
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_SALT) return;
  decoder_get_length(&decoder, &probe);
  uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];
  decoder_get_raw_buffer_value(&decoder, salt, sizeof(salt));
  // generate AES key using HKDF
  ndn_aes_key_t* sym_aes_key;
  ndn_key_storage_get_empty_aes_key(&sym_aes_key);
  uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];
  ndn_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
           salt, sizeof(salt), NULL, 0);
  ndn_aes_key_init(sym_aes_key, symmetric_key, sizeof(symmetric_key), SEC_BOOT_AES_KEY_ID);
  // prepare for the next interest: register the prefix
  ndn_name_t prefix_to_register;
  ndn_name_init(&prefix_to_register);
  ndn_name_append_component(&prefix_to_register, &trust_anchor_cert.name.components[0]);
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  ndn_name_tlv_encode(&encoder, &prefix_to_register);
  ndn_forwarder_add_route(m_sec_boot_state.face, encoder.output_value, encoder.offset);
  // send cert interest
  sec_boot_send_cert_interest();
}

int
sec_boot_send_sign_on_interest()
{
  int ret = 0;
  // generate the sign on interest  (1st interest)
  // make the Interest packet
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_name_append_string_component(&interest.name, "ndn", strlen("ndn"));
  ndn_name_append_string_component(&interest.name, "sign-on", strlen("sign-on"));
  // make Interest parameter
  // format: a name component, a list of services provided, the EC_pub_key
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  // append the identifier name component
  name_component_t device_identifier_comp;
  name_component_from_string(&device_identifier_comp, m_sec_boot_state.device_identifier,
                             m_sec_boot_state.identifier_size);
  name_component_tlv_encode(&encoder, &device_identifier_comp);
  // append the capabilities
  encoder_append_type(&encoder, TLV_SEC_BOOT_CAPACITIES);
  encoder_append_length(&encoder, m_sec_boot_state.list_size);
  encoder_append_raw_buffer_value(&encoder, m_sec_boot_state.service_list, m_sec_boot_state.list_size);
  // append the ecdh pub key, N1
  ndn_ecc_pub_t* dh_pub = NULL;
  ndn_key_storage_get_ecc_pub_key(SEC_BOOT_DH_KEY_ID, &dh_pub);
  encoder_append_type(&encoder, TLV_SEC_BOOT_N1_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(dh_pub), ndn_ecc_get_pub_key_size(dh_pub));
  // set parameter
  ndn_interest_set_Parameters(&interest, encoder.output_value, encoder.offset);
  // set must be fresh
  ndn_interest_set_MustBeFresh(&interest,true);
  // sign the interest
  ndn_name_t temp_name;
  ndn_signed_interest_ecdsa_sign(&interest, &interest.name, m_sec_boot_state.pre_installed_ecc_key);
  // send it out
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                       on_sign_on_data, on_sec_boot_sign_on_interest_timeout, NULL);
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send SEC BOOT sign on Interest packet with name: \n");
  ndn_name_print(&interest.name);
  return NDN_SUCCESS;
}

int
ndn_security_bootstrapping(ndn_face_intf_t* face,
                           const ndn_ecc_prv_t* pre_installed_prv_key, const ndn_hmac_key_t* pre_shared_hmac_key,
                           const char* device_identifier, size_t identifier_size,
                           const uint8_t* service_list, size_t list_size)
{
  // set ECC RNG backend
  ndn_rng_backend_t* rng_backend = ndn_rng_get_backend();
  ndn_ecc_set_rng(rng_backend->rng);

  // init key storage
  ndn_key_storage_init();

  // remember the state for future use
  m_sec_boot_state.face = face;
  m_sec_boot_state.pre_installed_ecc_key = pre_installed_prv_key;
  m_sec_boot_state.pre_shared_hmac_key = pre_shared_hmac_key;
  m_sec_boot_state.service_list = service_list;
  m_sec_boot_state.list_size = list_size;
  m_sec_boot_state.device_identifier = device_identifier;
  m_sec_boot_state.identifier_size = identifier_size;

  // preparation
  ndn_ecc_pub_t* dh_pub = NULL;
  ndn_ecc_prv_t* dh_prv = NULL;
  ndn_key_storage_get_empty_ecc_key(&dh_pub, &dh_prv);
  if (ndn_ecc_make_key(dh_pub, dh_prv, NDN_ECDSA_CURVE_SECP256R1, SEC_BOOT_DH_KEY_ID) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  // send the first interest out
  sec_boot_send_sign_on_interest();
  return NDN_SUCCESS;
}