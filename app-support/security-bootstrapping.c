/*
 * Copyright (C) 2018-2019
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
#include "../security/ndn-lite-rng.h"

typedef struct ndn_sec_boot_state {
  const uint8_t* service_list;
  size_t list_size;
  const ndn_ecc_prv_t* pre_installed_ecc_key;
  const ndn_hmac_key_t* pre_shared_hmac_key;
} ndn_sec_boot_state_t;

static uint8_t sec_boot_buf[4096];
static ndn_sec_boot_state_t m_sec_boot_state;
static const uint32_t SEC_BOOT_DH_KEY_ID = 10001;
static const uint32_t SEC_BOOT_AES_KEY_ID = 10002;

// some common rules: 1. keep keys in key_storage 2. delete the key from key storage if its not used any longer

void
sec_boot_after_bootstrapping()
{
  // set up self id and trust anchor
}

void
on_sec_boot_interest_timeout (void* userdata)
{
  // do nothing for now
  (void)userdata;
}

void
sec_boot_send_cert_interest() {
  // generate the cert interest (2nd interest)
  // send it out
}

void
on_sign_on_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_time_ms_t now = ndn_time_now_ms();
  uint32_t probe = 0;
  // parse content
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_Data) return;
  decoder_get_length(&decoder, &probe);
  ndn_data_t trust_anchor_cert;
  if (ndn_data_tlv_decode_hmac_verify(&trust_anchor_cert, data.content_value, probe,
                                      m_sec_boot_state.pre_shared_hmac_key) != NDN_SUCCESS) {
    return;
  }
  // key storage set trust anchor
  ndn_key_storage_set_trust_anchor(&trust_anchor_cert);
  // parse ecdh pub key
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_ECDH_PUB) return;
  decoder_get_length(&decoder, &probe);
  uint8_t dh_pub_buf[100];
  decoder_get_raw_buffer_value(&decoder, dh_pub_buf, probe);
  ndn_ecc_pub_t controller_pub_key;
  ndn_ecc_pub_init(&controller_pub_key, dh_pub_buf, probe, NDN_ECDSA_CURVE_SECP256R1, 1);
  ndn_ecc_prv_t* self_prv_key = NULL;
  ndn_key_storage_get_ecc_key(SEC_BOOT_DH_KEY_ID, NULL, &self_prv_key);
  // get shared secret using DH process
  uint8_t shared[32];
  ndn_ecc_dh_shared_secret(&controller_pub_key, self_prv_key, NDN_ECDSA_CURVE_SECP256R1, shared, sizeof(shared));
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
           salt, sizeof(salt));
  ndn_aes_key_init(&sym_aes_key, symmetric_key, sizeof(symmetric_key), SEC_BOOT_AES_KEY_ID);
  // send cert interest
  sec_boot_send_cert_interest();
}

int
sec_boot_send_sign_on_interest(const char* device_identifier, size_t device_identifier_len,
                               const uint8_t* service_list, size_t list_size)
{
  int ret = 0;
  // generate the sign on interest  (1st interest)
  ndn_ecc_pub_t* dh_pub = NULL;
  ndn_ecc_prv_t* dh_prv = NULL;
  ndn_key_storage_get_empty_ecc_key(&dh_pub, &dh_prv);
  if (ndn_ecc_make_key(dh_pub, dh_prv, NDN_ECDSA_CURVE_SECP256R1, SEC_BOOT_DH_KEY_ID) != NDN_SUCCESS) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  // make the Interest packet
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_name_append_string_component(&interest.name, "ndn", strlen("ndn"));
  ndn_name_append_string_component(&interest.name, "sign-on", strlen("sign-on"));

  // make Interest parameter
  // format: a name component (a string), a list of services provided, the EC_pub_key
  // append the identifier name component
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  name_component_t device_identifier_comp;
  name_component_from_string(&device_identifier_comp, device_identifier, device_identifier_len);
  encoder_append_type(&encoder,TLV_SSP_DEVICE_IDENTIFIER);
  encoder_append_length(&encoder, device_identifier_len);
  encoder_append_raw_buffer_value(&encoder,device_identifier,device_identifier_len);
  // append the capabilities
  encoder_append_type(&encoder, TLV_SSP_DEVICE_CAPABILITIES);
  encoder_append_length(&encoder, list_size);
  encoder_append_raw_buffer_value(&encoder, service_list, list_size);
  // append the ecdh pub key
  encoder_append_type(&encoder, TLV_SSP_N1_PUB);
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
                                       on_sign_on_data, on_sec_boot_interest_timeout, NULL);
  if (ret != 0) {
    printf("Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  printf("Send SD/META Interest packet with name: \n");
  ndn_name_print(&interest.name);
}

void
on_cert_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_digest_verify(&data, raw_data, data_size)) {
    printf("Decoding failed.\n");
  }
  printf("Receive SD related Data packet with name: \n");
  ndn_name_print(&data.name);
  ndn_time_ms_t now = ndn_time_now_ms();
  ndn_name_t service_full_name;
  uint32_t freshness_period = 0;
  // parse content
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  // TODO
  // finish the bootstrapping process
}

void
ndn_security_bootstrapping(const ndn_ecc_prv_t* pre_installed_prv_key, const ndn_hmac_key_t* pre_shared_hmac_key,
                           const char* device_identifier, size_t len,
                           const uint8_t* service_list, size_t list_size)
{
  // set ECC RNG backend
  ndn_rng_backend_t* rng_backend = ndn_rng_get_backend();
  ndn_ecc_set_rng(rng_backend->rng);

  // init key storage
  ndn_key_storage_init();

  // remember the state for future use
  m_sec_boot_state.pre_installed_ecc_key = pre_installed_prv_key;
  m_sec_boot_state.pre_shared_hmac_key = pre_shared_hmac_key;
  m_sec_boot_state.service_list = service_list;
  m_sec_boot_state.list_size = list_size;

  // send the first interest out
  sec_boot_send_sign_on_interest(device_identifier, len, service_list, list_size);
}