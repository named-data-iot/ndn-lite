/*
 * Copyright (C) 2018-2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ndn-sig-verifier.h"
#include "../encode/signed-interest.h"
#include "../encode/key-storage.h"

typedef struct ndn_sig_verifier_state {
  ndn_face_intf_t* face;
} ndn_sig_verifier_state_t;

typedef struct ndn_sig_verifier_userdata {
  bool is_interest;
  void* original_pkt;
  void* on_success_cbk;
  void* on_failure_cbk;
} ndn_sig_verifier_userdata_t;

static ndn_sig_verifier_userdata_t m_userdata;
static ndn_sig_verifier_state_t m_sig_verifier_state;
uint8_t verifier_buf[4096];

void
sig_verifier_on_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  ndn_sig_verifier_userdata_t* dataptr = (ndn_sig_verifier_userdata_t*)userdata;

  ndn_data_t cert;
  uint32_t start, end;
  ndn_data_tlv_decode_no_verify(&cert, raw_data, data_size, &start, &end);
  printf("Sig Verifier received certificate: \n");
  ndn_name_print(&cert.name);
  uint32_t keyid = key_id_from_key_name(&cert.signature.key_locator_name);
  ndn_ecc_pub_t* pub_key;
  ndn_key_storage_get_ecc_pub_key(keyid, &pub_key);
  bool is_success = false;
  if (pub_key != NULL) {
    int result = ndn_ecdsa_verify(raw_data + start, end - start,
                                  cert.signature.sig_value, cert.signature.sig_size, pub_key);
    if (result == NDN_SUCCESS) is_success = true;
  }
  if (is_success) {
    if (dataptr->is_interest) {
      on_int_verification_success on_success = (on_int_verification_success)(dataptr->on_success_cbk);
      on_success((ndn_interest_t*)dataptr->original_pkt);
    }
    else {
      on_data_verification_success on_success = (on_data_verification_success)(dataptr->on_success_cbk);
      on_success((ndn_data_t*)dataptr->original_pkt);
    }
  }
  else {
    if (dataptr->is_interest) {
    on_int_verification_failure on_failure = (on_int_verification_failure)(dataptr->on_failure_cbk);
    on_failure((ndn_interest_t*)dataptr->original_pkt);
    }
    else {
      on_data_verification_failure on_failure = (on_data_verification_failure)(dataptr->on_failure_cbk);
      on_failure((ndn_data_t*)dataptr->original_pkt);
    }
  }
}

void
sig_verifier_on_timeout(void* userdata)
{
  printf("\nSign Verifier cert fetch interest timeout\n");
  ndn_sig_verifier_userdata_t* dataptr = (ndn_sig_verifier_userdata_t*)userdata;
  if (dataptr->is_interest) {
    on_int_verification_failure on_failure = (on_int_verification_failure)(dataptr->on_failure_cbk);
    on_failure((ndn_interest_t*)dataptr->original_pkt);
  }
  else {
    on_data_verification_failure on_failure = (on_data_verification_failure)(dataptr->on_failure_cbk);
    on_failure((ndn_data_t*)dataptr->original_pkt);
  }
}

int
sig_verifier_on_interest(const uint8_t* raw_int, uint32_t raw_int_size, void* userdata)
{
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, raw_int, raw_int_size);
  printf("Sig Verifier received certificate fetching Interest: \n");
  ndn_name_print(&interest.name);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  if (ndn_name_is_prefix_of(&interest.name, &storage->self_cert.name) == NDN_SUCCESS) {
    ndn_encoder_t encoder;
    encoder_init(&encoder, verifier_buf, sizeof(verifier_buf));
    ndn_data_tlv_encode(&encoder, &storage->self_cert);
    ndn_forwarder_put_data(encoder.output_value, encoder.offset);
  }
  return NDN_FWD_STRATEGY_SUPPRESS;
}

int
ndn_sig_verifier_init(ndn_face_intf_t* face)
{
  m_sig_verifier_state.face = face;
  ndn_name_t prefix;
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  memcpy(&prefix, &storage->self_identity, sizeof(ndn_name_t));
  ndn_forwarder_register_name_prefix(&prefix, sig_verifier_on_interest, NULL);
  return NDN_SUCCESS;
}

void
ndn_sig_verifier_verify_int(const uint8_t* raw_pkt, size_t pkt_size, ndn_interest_t* interest,
                            on_int_verification_success on_success,
                            on_int_verification_failure on_failure)
{
  ndn_interest_from_block(interest, raw_pkt, pkt_size);
  if (!ndn_interest_is_signed(interest)) {
    on_success(interest);
    return;
  }
  if (interest->signature.sig_type < 0 || interest->signature.sig_type > 4) {
    on_failure(interest);
    return;
  }
  int result = 0;
  if (interest->signature.sig_type == NDN_SIG_TYPE_DIGEST_SHA256) {
    result = ndn_signed_interest_digest_verify(interest);
    if (result == NDN_SUCCESS) on_success(interest);
    else on_failure(interest);
  }
  if (interest->signature.enable_KeyLocator <= 0) {
    on_failure(interest);
    return;
  }
  uint32_t keyid = key_id_from_key_name(&interest->signature.key_locator_name);
  bool need_interest_out = false;
  if (interest->signature.sig_type == NDN_SIG_TYPE_ECDSA_SHA256) {
    ndn_ecc_pub_t* pub_key = NULL;
    ndn_key_storage_get_ecc_pub_key(keyid, &pub_key);
    if (pub_key == NULL) {
      need_interest_out = true;
    }
    else {
      result = ndn_signed_interest_ecdsa_verify(interest, pub_key);
      if (result == NDN_SUCCESS) on_success(interest);
      else on_failure(interest);
      return;
    }
  }
  else if (interest->signature.sig_type == NDN_SIG_TYPE_HMAC_SHA256) {
    ndn_hmac_key_t* hmac_key = NULL;
    ndn_key_storage_get_hmac_key(keyid, &hmac_key);
    if (hmac_key == NULL) {
      on_failure(interest);
      return;
    }
    else {
      result = ndn_signed_interest_hmac_verify(interest, hmac_key);
      if (result == NDN_SUCCESS) on_success(interest);
      else on_failure(interest);
      return;
    }
  }
  if (need_interest_out) {
    ndn_interest_t cert_interest;
    ndn_interest_init(&cert_interest);
    memcpy(&cert_interest.name, &interest->signature.key_locator_name, sizeof(ndn_name_t));
    ndn_interest_set_CanBePrefix(&cert_interest, true);
    ndn_interest_set_MustBeFresh(&cert_interest, true);
    ndn_encoder_t encoder;
    encoder_init(&encoder, verifier_buf, sizeof(verifier_buf));
    ndn_interest_tlv_encode(&encoder, &cert_interest);
    m_userdata.is_interest = true;
    m_userdata.original_pkt = (void*)interest;
    m_userdata.on_success_cbk = on_success;
    m_userdata.on_failure_cbk = on_failure;
    int ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                             sig_verifier_on_data, sig_verifier_on_timeout, &m_userdata);
    if (ret == NDN_FWD_NO_ROUTE) {
      ndn_forwarder_add_route_by_name(m_sig_verifier_state.face, &cert_interest.name);
      ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                           sig_verifier_on_data, sig_verifier_on_timeout, &m_userdata);
    }
    if (ret != 0) {
      printf("Fail to send out cert fetch Interest. Error Code: %d\n", ret);
      on_failure(interest);
      return;
    }
    printf("Send SD/META Interest packet with name: \n");
    ndn_name_print(&cert_interest.name);
    return;
  }
  on_failure(interest);
  return;
}

void
ndn_sig_verifier_verify_data(const uint8_t* raw_pkt, size_t pkt_size, ndn_data_t* data,
                             on_data_verification_success on_success,
                             on_data_verification_failure on_failure)
{
  uint32_t be_signed_start, be_signed_end;
  ndn_data_tlv_decode_no_verify(data, raw_pkt, pkt_size, &be_signed_start, &be_signed_end);
  if (data->signature.sig_type < 0 || data->signature.sig_type > 4) {
    on_failure(data);
    return;
  }
  int result = 0;
  if (data->signature.sig_type == NDN_SIG_TYPE_DIGEST_SHA256) {
    result = ndn_sha256_verify(raw_pkt + be_signed_start, be_signed_end - be_signed_start,
                               data->signature.sig_value, data->signature.sig_size);
    if (result == NDN_SUCCESS) on_success(data);
    else on_failure(data);
    return;
  }
  if (data->signature.enable_KeyLocator <= 0) {
    on_failure(data);
    return;
  }
  uint32_t keyid = key_id_from_key_name(&data->signature.key_locator_name);
  bool need_interest_out = false;
  if (data->signature.sig_type == NDN_SIG_TYPE_ECDSA_SHA256) {
    ndn_ecc_pub_t* pub_key = NULL;
    ndn_key_storage_get_ecc_pub_key(keyid, &pub_key);
    if (pub_key == NULL) {
      need_interest_out = true;
    }
    else {
      result = ndn_ecdsa_verify(raw_pkt + be_signed_start, be_signed_end - be_signed_start,
                                data->signature.sig_value, data->signature.sig_size, pub_key);
      if (result == NDN_SUCCESS) on_success(data);
      else on_failure(data);
      return;
    }
  }
  else if (data->signature.sig_type == NDN_SIG_TYPE_HMAC_SHA256) {
    ndn_hmac_key_t* hmac_key = NULL;
    ndn_key_storage_get_hmac_key(keyid, &hmac_key);
    if (hmac_key == NULL) {
      on_failure(data);
      return;
    }
    else {
      result = ndn_hmac_verify(raw_pkt + be_signed_start, be_signed_end - be_signed_start,
                               data->signature.sig_value, data->signature.sig_size, hmac_key);
      if (result == NDN_SUCCESS) on_success(data);
      else on_failure(data);
      return;
    }
  }
  if (need_interest_out) {
    ndn_interest_t cert_interest;
    memcmp(&cert_interest.name, &data->signature.key_locator_name, sizeof(ndn_name_t));
    ndn_interest_set_CanBePrefix(&cert_interest, true);
    ndn_interest_set_MustBeFresh(&cert_interest, true);
    ndn_encoder_t encoder;
    encoder_init(&encoder, verifier_buf, sizeof(verifier_buf));
    ndn_interest_tlv_encode(&encoder, &cert_interest);
    m_userdata.is_interest = false;
    m_userdata.original_pkt = (void*)data;
    m_userdata.on_success_cbk = on_success;
    m_userdata.on_failure_cbk = on_failure;
    ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                   sig_verifier_on_data, sig_verifier_on_timeout, &m_userdata);
    return;
  }
  on_failure(data);
  return;
}