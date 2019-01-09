/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sign-on-basic-client.h"

#include <string.h>

#include "../../../../../../ndn-error-code.h"
#include "../../../../../../ndn-constants.h"

#include "../../../../../../encode/tlv.h"
#include "../../../../../../encode/decoder.h"

#include "sign-on-basic-consts.h"
#include "security/sign-on-basic-sec-consts.h"
#include "sign-on-basic-impl-consts.h"
#include "../../tlv/sign-on-basic-tlv-impl-consts.h"
#include "variants/ecc_256/sign-on-basic-ecc-256-consts.h"

#include "../../tlv/sign-on-basic-tlv-helpers.h"

#include "../../../../../../adaptation/ndn-nrf-ble-adaptation/logger.h"

int sign_on_basic_client_init(
    uint8_t variant,
    struct sign_on_basic_client_t *sign_on_basic_client,
    const uint8_t *device_identifier_p, uint32_t device_identifier_len,
    const uint8_t *device_capabilities_p, uint32_t device_capabilities_len,
    const uint8_t *secure_sign_on_code_p,
    const uint8_t *KS_pub_p, uint32_t KS_pub_len,
    const uint8_t *KS_pri_p, uint32_t KS_pri_len) {

  APP_LOG_HEX("In sign_on_basic_client_init, value of device identifier:", device_identifier_p,
              device_identifier_len);
  APP_LOG_HEX("In sign_on_basic_client_init, value of device capabilities:", device_capabilities_p,
              device_capabilities_len);

  switch (variant) {
    case SIGN_ON_BASIC_VARIANT_ECC_256:
      sign_on_basic_client->secure_sign_on_code_len = SIGN_ON_BASIC_ECC_256_SECURE_SIGN_ON_CODE_LENGTH;
      APP_LOG("Secure sign-on ble basic client being initialized with ecc_256 variant\n");
      break;
    default:
      return NDN_SIGN_ON_BASIC_CLIENT_INIT_FAILED_UNRECOGNIZED_VARIANT;
      break;
  }

  int set_sec_intf_result = sign_on_basic_set_sec_intf(variant, sign_on_basic_client);
  if (set_sec_intf_result != NDN_SUCCESS)
    return NDN_SIGN_ON_BASIC_CLIENT_INIT_FAILED_TO_SET_SEC_INTF;

  memcpy(sign_on_basic_client->device_identifier_p, device_identifier_p, device_identifier_len);
  sign_on_basic_client->device_identifier_len = device_identifier_len;

  memcpy(sign_on_basic_client->device_capabilities_p, device_capabilities_p, device_capabilities_len);
  sign_on_basic_client->device_capabilities_len = device_capabilities_len;

  memcpy(sign_on_basic_client->secure_sign_on_code_p, secure_sign_on_code_p, 
    sign_on_basic_client->secure_sign_on_code_len);

  memcpy(sign_on_basic_client->KS_pub_p, KS_pub_p, KS_pub_len);
  sign_on_basic_client->KS_pub_len = KS_pub_len;

  memcpy(sign_on_basic_client->KS_pri_p, KS_pri_p, KS_pri_len);
  sign_on_basic_client->KS_pri_len = KS_pri_len;

  APP_LOG("Initialized sign-on client with variant type: %d\n", variant);

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_NOT_STARTED;

  return NDN_SUCCESS;
}

int cnstrct_btstrp_rqst(uint8_t *buf_p, uint32_t buf_len,
    uint32_t *output_len_p,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  // generate N1 key pair here
  if (!sign_on_basic_client->sec_intf.gen_n1_keypair(
          sign_on_basic_client->N1_pub_p, SIGN_ON_BASIC_CLIENT_N1_PUB_MAX_LENGTH,
          &sign_on_basic_client->N1_pub_len,
          sign_on_basic_client->N1_pri_p, SIGN_ON_BASIC_CLIENT_N1_PRI_MAX_LENGTH,
          &sign_on_basic_client->N1_pri_len)) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_N1_KEYPAIR;
  }

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  int ndn_encoder_success = 0;
  uint32_t btstrp_rqst_tlv_val_len = 0;
  uint32_t btstrp_rqst_sig_tlv_val_len = 0;

  btstrp_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_DEVICE_IDENTIFIER,
                                                      sign_on_basic_client->device_identifier_len);
  APP_LOG("btstrp_rqst_tlv_val_len after adding device identifier tlv block length: %d\n", btstrp_rqst_tlv_val_len);
  btstrp_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_DEVICE_CAPABILITIES,
                                                      sign_on_basic_client->device_capabilities_len);
  APP_LOG("btstrp_rqst_tlv_val_len after adding device capabilities tlv block length: %d\n", btstrp_rqst_tlv_val_len);
  btstrp_rqst_tlv_val_len += encoder_probe_block_size(TLV_SSP_N1_PUB,
                                                      sign_on_basic_client->N1_pub_len);
  APP_LOG("btstrp_rqst_tlv_val_len after adding N1 pub tlv block length: %d\n", btstrp_rqst_tlv_val_len);
  btstrp_rqst_sig_tlv_val_len = sign_on_basic_client->sec_intf.get_btstrp_rqst_sig_len();
  uint32_t btstrp_rqst_sig_tlv_len_field_size = encoder_get_var_size(btstrp_rqst_sig_tlv_val_len);
  uint32_t btstrp_rqst_sig_tlv_type_field_size = encoder_get_var_size(TLV_SSP_SIGNATURE);
  btstrp_rqst_tlv_val_len += btstrp_rqst_sig_tlv_type_field_size;
  btstrp_rqst_tlv_val_len += btstrp_rqst_sig_tlv_len_field_size;
  btstrp_rqst_tlv_val_len += btstrp_rqst_sig_tlv_val_len;
  APP_LOG("btstrp_rqst_tlv_val_len after adding signature tlv block length: %d\n", btstrp_rqst_tlv_val_len);

  APP_LOG("btstrp_rqst_tlv_val_len: %d\n", btstrp_rqst_tlv_val_len);

  uint32_t btstrp_rqst_tlv_type_field_size = encoder_get_var_size(TLV_SSP_BOOTSTRAPPING_REQUEST);
  uint32_t btstrp_rqst_tlv_len_field_size = encoder_get_var_size(btstrp_rqst_tlv_val_len);

  uint32_t btstrp_rqst_total_len = btstrp_rqst_tlv_val_len + btstrp_rqst_tlv_type_field_size + 
                                   btstrp_rqst_tlv_len_field_size;
  if (buf_len < btstrp_rqst_total_len) {
    APP_LOG("In cnstrct_btstrp_rqst, buf_len (%d) was less than total size of bootstrapping request (%d)\n",
            buf_len, btstrp_rqst_total_len);
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_BUFFER_TOO_SHORT;
  }

  ndn_encoder_t encoder;
  encoder_init(&encoder, buf_p, buf_len);

  // append the bootstrapping request tlv type and length
  if (encoder_append_type(&encoder, TLV_SSP_BOOTSTRAPPING_REQUEST) != ndn_encoder_success) {
     APP_LOG("In cnstrct_btstrp_rqst, encoder_append_type for bootstrapping request tlv type failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;   
  }
  if (encoder_append_length(&encoder, btstrp_rqst_tlv_val_len) != ndn_encoder_success) {
     APP_LOG("In cnstrct_btstrp_rqst, encoder_append_length for bootstrapping request tlv length failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;   
  }
  
  // append the device identifier
  if (encoder_append_type(&encoder, TLV_SSP_DEVICE_IDENTIFIER) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_type for device identifier failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->device_identifier_len) != ndn_encoder_success)  {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_length for device identifier failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->device_identifier_p,
                                      sign_on_basic_client->device_identifier_len) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_raw_buffer_value for device identifier failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  // append the device capabilities
  if (encoder_append_type(&encoder, TLV_SSP_DEVICE_CAPABILITIES) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_type for device capabilities failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->device_capabilities_len) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_length for device capabilities failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->device_capabilities_p,
                                      sign_on_basic_client->device_capabilities_len) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_raw_buffer_value for device capabilities failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  // append N1 pub
  if (encoder_append_type(&encoder, TLV_SSP_N1_PUB) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_type for N1 pub failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_length(&encoder, sign_on_basic_client->N1_pub_len) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_length for N1 pub failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }
  if (encoder_append_raw_buffer_value(&encoder, sign_on_basic_client->N1_pub_p,
                                      sign_on_basic_client->N1_pub_len) != ndn_encoder_success) {
    APP_LOG("In cnstrct_btstrp_rqst, encoder_append_raw_buffer_value for N1 pub failed.\n");
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  uint8_t *sig_payload_begin = buf_p + btstrp_rqst_tlv_type_field_size + btstrp_rqst_tlv_len_field_size;
  uint32_t sig_payload_size = encoder.offset - btstrp_rqst_tlv_type_field_size - btstrp_rqst_tlv_len_field_size;

  APP_LOG_HEX("Signature payload of bootstrapping request:", sig_payload_begin, sig_payload_size);

  // calculate the signature 
  uint8_t temp_sig_buf[SIG_GENERATION_BUF_LENGTH];
  uint32_t sig_size = 0;
  if (!sign_on_basic_client->sec_intf.gen_btstrp_rqst_sig(sign_on_basic_client->KS_pri_p,
                                                          sig_payload_begin, sig_payload_size,
                                                          temp_sig_buf, SIG_GENERATION_BUF_LENGTH, 
                                                          &sig_size)) {
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_SIG;
  }

  if (btstrp_rqst_sig_tlv_val_len != sig_size) {
    APP_LOG("Signature size returned by get_btstrp_rqst_sig_len (%d) "
            "and gen_btstrp_rqst_sig (%d) did not match.\n", btstrp_rqst_sig_tlv_val_len, sig_size);
    return NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED;
  }

  encoder_append_type(&encoder, TLV_SSP_SIGNATURE);
  encoder_append_length(&encoder, sig_size);
  encoder_append_raw_buffer_value(&encoder, temp_sig_buf, sig_size);

  *output_len_p = encoder.offset;

  APP_LOG_HEX("Hex of fully generated bootstrapping request:", buf_p, *output_len_p);

  return NDN_SUCCESS;
  
}

int prcs_btstrp_rqst_rspns(const uint8_t *btstrp_rqst_rspns_buf_p,
    uint32_t btstrp_rqst_rspns_buf_len,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  APP_LOG("Process bootstrapping request response got called.\n");

  APP_LOG("Length of bootstrapping request response tlv block: %d\n", btstrp_rqst_rspns_buf_len);
  APP_LOG_HEX("Full contents of bootstrapping request response:", btstrp_rqst_rspns_buf_p, btstrp_rqst_rspns_buf_len);

  // define pointers to data / lengths of data to be copied at the end, after processing is finished,
  // so that no internal state of the sign on basic client object is modified until after the whole
  // message has been processed successfully
  uint8_t *N2_pub_p;
  uint32_t N2_pub_len;
  uint8_t *trust_anchor_p;
  uint32_t trust_anchor_len;

  int ndn_decoder_success = 0;
  ndn_decoder_t decoder;
  decoder_init(&decoder, btstrp_rqst_rspns_buf_p, btstrp_rqst_rspns_buf_len);

  uint32_t current_tlv_type;
  uint32_t current_tlv_length;
  uint8_t *btstrp_rqst_rspns_tlv_val_buf_p;
  uint32_t btstrp_rqst_rspns_tlv_val_len;
  uint8_t *btstrp_rqst_rspns_tlv_sig_p;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_BTSTRP_RQST_RSPNS;
  }
  if (current_tlv_type != TLV_SSP_BOOTSTRAPPING_REQUEST_RESPONSE) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_BTSTRP_RQST_RSPNS;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_BTSTRP_RQST_RSPNS;
  }

  btstrp_rqst_rspns_tlv_val_buf_p = btstrp_rqst_rspns_buf_p + decoder.offset;
  btstrp_rqst_rspns_tlv_val_len = current_tlv_length;

  APP_LOG("Length of bootstrapping request response: %d\n", btstrp_rqst_rspns_tlv_val_len);
  APP_LOG_HEX("Value of bootstrapping request response:", btstrp_rqst_rspns_tlv_val_buf_p,
              btstrp_rqst_rspns_tlv_val_len);

  // check for the N2 pub tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv type of N2 pub.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }
  if (current_tlv_type != TLV_SSP_N2_PUB) {
    APP_LOG("Did not get expected tlv type when parsing for N2 pub in bootstrapping "
            "request response: got %d.\n", current_tlv_type);
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv length of N2 pub.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }
  N2_pub_p = btstrp_rqst_rspns_buf_p + decoder.offset;
  N2_pub_len = current_tlv_length;
  APP_LOG_HEX("Value of N2 pub (ndn decoder):", N2_pub_p, N2_pub_len);
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to move ndn decoder offset past N2 pub tlv value.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB;
  }

  // check for the trust anchor certificate tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv type of trust anchor certificate.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  }
  if (current_tlv_type != TLV_SSP_ANCHOR_CERTIFICATE) {
    APP_LOG("Did not get expected tlv type when parsing for trust anchor cert in bootstrapping "
            "request response: got %d.\n", current_tlv_type);
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  } 
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv length of trust anchor certificate.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  }
  trust_anchor_p = btstrp_rqst_rspns_buf_p + decoder.offset;
  trust_anchor_len = current_tlv_length;
  APP_LOG("Length of trust anchor certificate (ndn_decoder): %d\n", trust_anchor_len);
  APP_LOG_HEX("Value of trust anchor certificate (ndn decoder):", trust_anchor_p, trust_anchor_len);
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to move ndn decoder offset past trust anchor cert tlv value.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT;
  }

  // check for signature tlv block and move the decoder to its tlv value

  btstrp_rqst_rspns_tlv_sig_p = btstrp_rqst_rspns_buf_p + decoder.offset;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv type of bootstrapping request response signature.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (current_tlv_type != TLV_SSP_SIGNATURE) {
    APP_LOG("Did not get expected tlv type when parsing for signature in bootstrapping "
            "request response: got %d.\n", current_tlv_type);
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv length of bootstrapping request response signature.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }

  APP_LOG_HEX("First three bytes after btstrp_rqst_rspns_tlv_sig_p:", btstrp_rqst_rspns_tlv_sig_p, 3);

  const uint8_t *sig_begin = btstrp_rqst_rspns_buf_p + decoder.offset;
  uint32_t sig_len = current_tlv_length;
  const uint8_t *sig_payload_begin = btstrp_rqst_rspns_tlv_val_buf_p;
  uint32_t sig_payload_len = btstrp_rqst_rspns_tlv_sig_p - btstrp_rqst_rspns_tlv_val_buf_p;

  APP_LOG_HEX("Value of signature of bootstrapping request response", sig_begin, sig_len);
  APP_LOG_HEX("Value of signature payload of bootstrapping request response", sig_payload_begin, sig_payload_len);

  if (!sign_on_basic_client->sec_intf.vrfy_btstrp_rqst_rspns_sig(
          sig_payload_begin, sig_payload_len,
          sig_begin, sig_len,
          sign_on_basic_client->secure_sign_on_code_p,
          sign_on_basic_client->secure_sign_on_code_len)) {
    APP_LOG("Failed to verify bootstrapping request signature.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE;
  }

  //***************************************************//

  if (!sign_on_basic_client->sec_intf.gen_kt(N2_pub_p, N2_pub_len,
                                             sign_on_basic_client->N1_pri_p, sign_on_basic_client->N1_pri_len,
                                             sign_on_basic_client->KT_p,
                                             SIGN_ON_BASIC_CLIENT_KT_MAX_LENGTH,
                                             &sign_on_basic_client->KT_len)) {
    APP_LOG("Failed to generate shared secret.\n");
    return NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GENERATE_KT;
  }

  //***************************************************//

  // now that the entire bootstrapping request respone has been processed successfully, can modify internal state
  // of sign on client object
  memcpy(sign_on_basic_client->N2_pub_p, N2_pub_p, (size_t) N2_pub_len);
  sign_on_basic_client->N2_pub_len = N2_pub_len;
  memcpy(sign_on_basic_client->trust_anchor_cert_p, trust_anchor_p, (size_t) trust_anchor_len);
  sign_on_basic_client->trust_anchor_cert_len = trust_anchor_len;

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_PROCESSED_BOOTSTRAPPING_REQUEST_RESPONSE;
  return NDN_SUCCESS;
}

int cnstrct_cert_rqst(uint8_t *buf_p, uint32_t buf_len, uint32_t *output_len_p,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  APP_LOG("Construct certificate request got called.\n");

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  if (buf_len < 1) {
    APP_LOG("The buffer passed into construct certificate request was too short.\n");
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_BUFFER_TOO_SHORT;
  }

  int certificateRequestTlvTypePosition = 0;
  int certificateRequestTlvLengthPosition = 1;

  int currentOffset = 0;
  uint8_t arbitraryValue = 0x03;

  // add TLV_TYPE_AND_LENGTH_SIZE to account for the certificate request tlv type and length;
  // these will be filled in at the end
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t device_identifier_len = sign_on_basic_client->device_identifier_len;
  buf_p[currentOffset] = TLV_SSP_DEVICE_IDENTIFIER;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = device_identifier_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->device_identifier_p,
      device_identifier_len * sizeof(uint8_t));
  currentOffset += device_identifier_len;

  APP_LOG_HEX("Value of N1_pub in sign_on_basic_client", sign_on_basic_client->N1_pub_p, sign_on_basic_client->N1_pub_len);

  uint8_t N1_pub_len = sign_on_basic_client->N1_pub_len;
  buf_p[currentOffset] = TLV_SSP_N1_PUB;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = N1_pub_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->N1_pub_p,
      N1_pub_len * sizeof(uint8_t));
  currentOffset += N1_pub_len;

  APP_LOG_HEX("Value of N1_pub put into cert request", buf_p + currentOffset - N1_pub_len, N1_pub_len);

  // need to calculate N2 pub digest here
  //**************************************//

  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->N2_pub_p, 
    sign_on_basic_client->N2_pub_len, digest_buffer)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_N2_PUB_HASH;
  }

  //**************************************//

  uint32_t N2_pub_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = TLV_SSP_N2_PUB_DIGEST;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = N2_pub_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, N2_pub_digest_len * sizeof(uint8_t));
  currentOffset += N2_pub_digest_len;

  // need to calculate trust anchor certificate digest here
  //**************************************//

  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->trust_anchor_cert_p,
            sign_on_basic_client->trust_anchor_cert_len, digest_buffer)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_TRUST_ANCHOR_CERT_HASH;
  }

  //**************************************//

  uint32_t trust_anchor_cert_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = TLV_SSP_TRUST_ANCHOR_CERTIFICATE_DIGEST;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = trust_anchor_cert_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, trust_anchor_cert_digest_len * sizeof(uint8_t));
  currentOffset += trust_anchor_cert_digest_len;

  // special part of construction: calculate signature over all bytes of certificate request besides the signature
  // tlv block, and append it to the end

  uint32_t signatureSize = 0;
  uint32_t sig_payload_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;
  uint32_t offsetForSignatureEncoding = 8;
  uint32_t encodedSignatureSize;

  // generate signature of bootstrapping request
  //**************************************//

  uint32_t sig_payload_end_offset = currentOffset;
  // need to subtract TLV_TYPE_AND_LENGTH_SIZE to account for fact that packet header is not included in signature
  uint32_t sig_payload_size = sig_payload_end_offset - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;
  // need to add TLV_TYPE_AND_LENGTH_SIZE to buf_p to account for fact that packet header is not included in signature
  uint8_t *sig_payload_begin = buf_p + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t certRqstSigBuf[SIG_GENERATION_BUF_LENGTH];

  if (!sign_on_basic_client->sec_intf.gen_cert_rqst_sig(sign_on_basic_client->KS_pri_p, 
                                                        sig_payload_begin, sig_payload_size,
                                                        certRqstSigBuf, SIG_GENERATION_BUF_LENGTH, 
                                                        &encodedSignatureSize)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_SIG;
  }

  //**************************************//

  // add the signature to the packet
  memcpy(buf_p + currentOffset + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE, certRqstSigBuf, encodedSignatureSize);

  buf_p[currentOffset] = TLV_SSP_SIGNATURE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = (uint8_t)encodedSignatureSize;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  currentOffset += encodedSignatureSize;

  // set the first byte of the buffer to be the certificate request tlv type
  buf_p[certificateRequestTlvTypePosition] = TLV_SSP_CERTIFICATE_REQUEST;

  // set the second byte of the buffer to be the length of the entire certificate request, excluding the
  // certificate request tlv type and certificate request tlv length (i.e., total buffer size - 2)
  buf_p[certificateRequestTlvLengthPosition] =
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + device_identifier_len +        // to account for device identifier TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + N1_pub_len +                   // to account for N1 pub TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + N2_pub_digest_len +            // to account for N2 pub digest TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + trust_anchor_cert_digest_len + // to account for trust anchor digest TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + encodedSignatureSize;          // to account for signature TLV

  *output_len_p = SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + buf_p[1]; // length of packet header tlv type and length plus rest of packet

  APP_LOG_HEX("Bytes of generated certificate request:", buf_p, *output_len_p);

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_GENERATED_CERTIFICATE_REQUEST;
  return NDN_SUCCESS;
}

int prcs_cert_rqst_rspns(const uint8_t *cert_rqst_rspns_buf_p,
    uint32_t cert_rqst_rspns_buf_len,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  // declare pointers to KD pri decrypted and KD pub certificate ahead of time,
  // so that modification of internal state of sign on basic client isn't done until after
  // entire certificate request response message is successfully processed
  uint8_t *KD_pri_encrypted_p;
  uint32_t KD_pri_encrypted_len;
  uint8_t *KD_pri_decrypted_p;
  uint32_t KD_pri_decrypted_len;
  uint8_t *KD_pub_cert_p;
  uint32_t KD_pub_cert_len;

  APP_LOG("Process certificate request response got called.\n");

  int ndn_decoder_success = 0;
  ndn_decoder_t decoder;
  decoder_init(&decoder, cert_rqst_rspns_buf_p, cert_rqst_rspns_buf_len);

  uint32_t current_tlv_type;
  uint32_t current_tlv_length;
  uint8_t *cert_rqst_rspns_tlv_val_buf_p;
  uint32_t cert_rqst_rspns_tlv_val_len;
  uint8_t *cert_rqst_rspns_tlv_sig_p;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_CERT_RQST_RSPNS;
  }
  if (current_tlv_type != TLV_SSP_CERTIFICATE_REQUEST_RESPONSE) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_CERT_RQST_RSPNS;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_CERT_RQST_RSPNS;
  }

  cert_rqst_rspns_tlv_val_buf_p = cert_rqst_rspns_buf_p + decoder.offset;
  cert_rqst_rspns_tlv_val_len = current_tlv_length;

  APP_LOG("Length of certificate request response: %d\n", cert_rqst_rspns_tlv_val_len);
  APP_LOG_HEX("Value of certificate request response:", cert_rqst_rspns_tlv_val_buf_p,
               cert_rqst_rspns_tlv_val_len);

  // check for the KD pri encrypted tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv type of KD pri encrypted.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }
  if (current_tlv_type != TLV_SSP_KD_PRI_ENCRYPTED) {
    APP_LOG("Did not get expected tlv type when parsing for KD pri encrypted in bootstrapping "
            "request response: got %d.\n", current_tlv_type);
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv length of KD pri encrypted.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }
  KD_pri_encrypted_p = cert_rqst_rspns_buf_p + decoder.offset;
  KD_pri_encrypted_len = current_tlv_length;
  APP_LOG_HEX("Value of KD pri encrypted (ndn decoder):", KD_pri_encrypted_p, KD_pri_encrypted_len);
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to move ndn decoder offset past KD pri encrypted tlv value.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC;
  }

  // check for the KD pub certificate tlv block and move the decoder offset past it
  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv type of KD pub certificate.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  }
  if (current_tlv_type != TLV_SSP_KD_PUB_CERTIFICATE) {
    APP_LOG("Did not get expected tlv type when parsing for KD pub certificate in bootstrapping "
            "request response: got %d.\n", current_tlv_type);
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  } 
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv length of KD pub certificate.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  }
  KD_pub_cert_p = cert_rqst_rspns_buf_p + decoder.offset;
  KD_pub_cert_len = current_tlv_length;
  APP_LOG_HEX("Value of KD pub certificate (ndn decoder):", KD_pub_cert_p, KD_pub_cert_len);
  if (decoder_move_forward(&decoder, current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to move ndn decoder offset past KD pub cert tlv value.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT;
  }

  // check for signature tlv block and move the decoder to its tlv value

  cert_rqst_rspns_tlv_sig_p = cert_rqst_rspns_buf_p + decoder.offset;

  if (decoder_get_type(&decoder, &current_tlv_type) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv type of certificate request response signature.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (current_tlv_type != TLV_SSP_SIGNATURE) {
    APP_LOG("Did not get expected tlv type when parsing for signature in certificate "
            "request response: got %d.\n", current_tlv_type);
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }
  if (decoder_get_length(&decoder, &current_tlv_length) != ndn_decoder_success) {
    APP_LOG("Failed to get tlv length of certificate request response signature.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG;
  }

  const uint8_t *sig_begin = cert_rqst_rspns_buf_p + decoder.offset;
  uint32_t sig_len = current_tlv_length;
  const uint8_t *sig_payload_begin = cert_rqst_rspns_tlv_val_buf_p;
  uint32_t sig_payload_len = cert_rqst_rspns_tlv_sig_p - cert_rqst_rspns_tlv_val_buf_p;

  APP_LOG_HEX("Value of signature of certificate request response", sig_begin, sig_len);
  APP_LOG_HEX("Value of signature payload of certificate request response", sig_payload_begin, sig_payload_len);

  if (!sign_on_basic_client->sec_intf.vrfy_cert_rqst_rspns_sig(
          sig_payload_begin, sig_payload_len,
          sig_begin, sig_len,
          sign_on_basic_client->KT_p,
          sign_on_basic_client->KT_len)) {
    APP_LOG("Failed to verify certificate request signature.\n");
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE;
  }

  //***************************************************//

  APP_LOG("Doing decryption of Kd pri by Kt.\n");

  APP_LOG_HEX("Value of Kt:", sign_on_basic_client->KT_p, sign_on_basic_client->KT_len);

  uint8_t KD_pri_decrypted_temp_buf[SIGN_ON_BASIC_CLIENT_KD_PRI_MAX_LENGTH];

  if (!sign_on_basic_client->sec_intf.decrypt_kd_pri(
      sign_on_basic_client->KT_p,
      sign_on_basic_client->KT_len,
      KD_pri_encrypted_p, KD_pri_encrypted_len,
      KD_pri_decrypted_temp_buf, 
      sizeof(KD_pri_decrypted_temp_buf),
      &KD_pri_decrypted_len)) {
    return NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_DECRYPT_KD_PRI;
  }

  APP_LOG_HEX("Kd pri decrypted:", KD_pri_decrypted_temp_buf, KD_pri_decrypted_len);

  KD_pri_decrypted_p = KD_pri_decrypted_temp_buf;

  //**********************************************************//

  // now that entire message has been processed successfully, modify internal state of sign on basic client
  memcpy(sign_on_basic_client->KD_pri_p, KD_pri_decrypted_p, KD_pri_decrypted_len);
  sign_on_basic_client->KD_pri_len = KD_pri_decrypted_len;
  memcpy(sign_on_basic_client->KD_pub_cert_p, KD_pub_cert_p, KD_pub_cert_len);
  sign_on_basic_client->KD_pub_cert_len = KD_pub_cert_len;

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_PROCESSED_CERTIFICATE_REQUEST_RESPONSE;
  return NDN_SUCCESS;
}

int cnstrct_fin_msg(uint8_t *buf_p, uint32_t buf_len, uint32_t *output_len_p,
                            struct sign_on_basic_client_t *sign_on_basic_client) {

  APP_LOG("Construct finish message got called.\n");

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  if (buf_len < 1) {
    APP_LOG("The buffer passed into construct finish message was too short.\n");
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_BUFFER_TOO_SHORT;
  }

  int finishMessageTlvTypePosition = 0;
  int finishMessageTlvLengthPosition = 1;

  int currentOffset = 0;

  // add TLV_TYPE_AND_LENGTH_SIZE to account for the finish message tlv type and length;
  // these will be filled in at the end
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t device_identifier_len = sign_on_basic_client->device_identifier_len;
  buf_p[currentOffset] = TLV_SSP_DEVICE_IDENTIFIER;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = device_identifier_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->device_identifier_p,
      device_identifier_len * sizeof(uint8_t));
  currentOffset += device_identifier_len;

  uint8_t N1_pub_len = sign_on_basic_client->N1_pub_len;
  buf_p[currentOffset] = TLV_SSP_N1_PUB;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = N1_pub_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->N1_pub_p,
      N1_pub_len * sizeof(uint8_t));
  currentOffset += N1_pub_len;

  // need to calculate N2 pub digest here
  //**************************************//

  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->N2_pub_p, 
    sign_on_basic_client->N2_pub_len, digest_buffer)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_N2_PUB_HASH;
  }

  //**************************************//

  uint32_t N2_pub_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = TLV_SSP_N2_PUB_DIGEST;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = N2_pub_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, N2_pub_digest_len * sizeof(uint8_t));
  currentOffset += N2_pub_digest_len;

  // need to calculate trust anchor certificate digest here
  //**************************************//

  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->trust_anchor_cert_p,
          sign_on_basic_client->trust_anchor_cert_len, digest_buffer)) {
    return NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_TRUST_ANCHOR_CERT_HASH;
  }

  //**************************************//

  uint32_t trust_anchor_cert_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = TLV_SSP_TRUST_ANCHOR_CERTIFICATE_DIGEST;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = trust_anchor_cert_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, trust_anchor_cert_digest_len * sizeof(uint8_t));
  currentOffset += trust_anchor_cert_digest_len;

  // special part of construction: calculate signature over all bytes of certificate request besides the signature
  // tlv block, and append it to the end

  uint32_t signatureSize = 0;
  uint32_t sig_payload_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;
  uint32_t offsetForSignatureEncoding = 8;
  uint32_t encodedSignatureSize;

  // generate signature of bootstrapping request
  //**************************************//

  uint32_t sig_payload_end_offset = currentOffset;
  // need to subtract TLV_TYPE_AND_LENGTH_SIZE to account for fact that packet header is not included in signature
  uint32_t sig_payload_size = sig_payload_end_offset - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;
  // need to add TLV_TYPE_AND_LENGTH_SIZE to buf_p to account for fact that packet header is not included in signature
  uint8_t *sig_payload_begin = buf_p + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t certRqstSigBuf[SIG_GENERATION_BUF_LENGTH];

  if (!sign_on_basic_client->sec_intf.gen_fin_msg_sig(sign_on_basic_client->KS_pri_p,
                                                      sig_payload_begin, sig_payload_size,
                                                      certRqstSigBuf, SIG_GENERATION_BUF_LENGTH, 
                                                      &encodedSignatureSize)) {
    return NDN_SIGN_ON_CNSTRCT_FIN_MSG_FAILED_TO_GENERATE_SIG;
  }

  //**************************************//

  // add the signature to the packet
  memcpy(buf_p + currentOffset + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE, certRqstSigBuf, encodedSignatureSize);

  buf_p[currentOffset] = TLV_SSP_SIGNATURE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = (uint8_t)encodedSignatureSize;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  currentOffset += encodedSignatureSize;

  // set the first byte of the buffer to be the certificate request tlv type
  buf_p[finishMessageTlvTypePosition] = TLV_SSP_FINISH_MESSAGE;

  // set the second byte of the buffer to be the length of the entire certificate request, excluding the
  // certificate request tlv type and certificate request tlv length (i.e., total buffer size - 2)
  buf_p[finishMessageTlvLengthPosition] =
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + device_identifier_len +        // to account for device identifier TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + N1_pub_len +                   // to account for N1 pub TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + N2_pub_digest_len +            // to account for N2 pub digest TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + trust_anchor_cert_digest_len + // to account for trust anchor digest TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + encodedSignatureSize;          // to account for signature TLV

  *output_len_p = SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + buf_p[1]; // length of packet header tlv type and length plus rest of packet

  APP_LOG_HEX("Bytes of generated finish message:", buf_p, *output_len_p);

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_GENERATED_FINISH_MESSAGE;
  return NDN_SUCCESS;
}