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

#include "sign-on-basic-consts.h"
#include "security/sign-on-basic-sec-consts.h"
#include "sign-on-basic-impl-consts.h"
#include "../../tlv/sign-on-basic-tlv-impl-consts.h"
#include "variants/ecc_256/sign-on-basic-ecc-256-consts.h"

#include "../../tlv/sign-on-basic-tlv-helpers.h"
#include "../../../../../../logger.h"

enum sign_on_basic_client_init_result sign_on_basic_client_init(
    uint8_t variant,
    struct sign_on_basic_client_t *sign_on_basic_client,
    const uint8_t *device_identifier_p, uint16_t device_identifier_len,
    const uint8_t *device_capabilities_p, uint16_t device_capabilities_len,
    const uint8_t *secure_sign_on_code_p,
    const uint8_t *KS_pub_p, uint16_t KS_pub_len,
    const uint8_t *KS_pri_p, uint16_t KS_pri_len) {

  switch (variant) {
    case SIGN_ON_BASIC_VARIANT_ECC_256:
      sign_on_basic_client->secure_sign_on_code_len = SIGN_ON_BASIC_ECC_256_SECURE_SIGN_ON_CODE_LENGTH;
      APP_LOG("Secure sign-on ble basic client being initialized with ecc_256 variant\n");
      break;
    default:
      return SIGN_ON_BASIC_CLIENT_INIT_FAILED_UNRECOGNIZED_VARIANT;
      break;
  }

  enum sign_on_basic_set_sec_intf_result set_sec_intf_result;
  set_sec_intf_result = sign_on_basic_set_sec_intf(variant, sign_on_basic_client);
  if (set_sec_intf_result != SIGN_ON_BASIC_SET_SEC_INTF_SUCCESS)
    return SIGN_ON_BASIC_CLIENT_INIT_FAILED_TO_SET_SEC_INTF;

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

  return SIGN_ON_BASIC_CLIENT_INIT_SUCCESS;
}

enum cnstrct_btstrp_rqst_result cnstrct_btstrp_rqst(uint8_t *buf_p, uint16_t buf_len,
    uint16_t *output_len_p,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  if (buf_len < 1)
    return CNSTRCT_BTSTRP_RQST_BUFFER_TOO_SHORT;

  // generate N1 key pair here
  if (!sign_on_basic_client->sec_intf.gen_n1_keypair(
          sign_on_basic_client->N1_pub_p, SIGN_ON_BASIC_CLIENT_N1_PUB_MAX_LENGTH,
          &sign_on_basic_client->N1_pub_len,
          sign_on_basic_client->N1_pri_p, SIGN_ON_BASIC_CLIENT_N1_PRI_MAX_LENGTH,
          &sign_on_basic_client->N1_pri_len)) {
    return CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_N1_KEYPAIR;
  }

  APP_LOG_HEX("Bytes of generated N1 pub:", sign_on_basic_client->N1_pub_p, sign_on_basic_client->N1_pub_len);
  APP_LOG_HEX("Bytes of generated N1 pri:", sign_on_basic_client->N1_pri_p, sign_on_basic_client->N1_pri_len);

  int bootstrappingRequestTlvTypePosition = 0;
  int bootstrappingRequestTlvLengthPosition = 1;

  int currentOffset = 0;
  uint8_t arbitraryValue = 0x03;

  // add TLV_TYPE_AND_LENGTH_SIZE to account for the bootstrapping request tlv type and length;
  // these will be filled in at the end
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t device_identifier_len = sign_on_basic_client->device_identifier_len;
  buf_p[currentOffset] = SECURE_SIGN_ON_DEVICE_IDENTIFIER_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = device_identifier_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->device_identifier_p,
      device_identifier_len * sizeof(uint8_t));
  currentOffset += device_identifier_len;

  uint8_t device_capabilities_len = sign_on_basic_client->device_capabilities_len;
  buf_p[currentOffset] = SECURE_SIGN_ON_DEVICE_CAPABILITIES_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = device_capabilities_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->device_capabilities_p,
      device_capabilities_len * sizeof(uint8_t));
  currentOffset += device_capabilities_len;

  uint8_t N1_pub_len = sign_on_basic_client->N1_pub_len;
  buf_p[currentOffset] = SECURE_SIGN_ON_N1_PUB_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = N1_pub_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->N1_pub_p, N1_pub_len * sizeof(uint8_t));
  currentOffset += N1_pub_len;

  // special part of construction: calculate signature over all bytes of bootstrapping request besides the signature
  // tlv block, and append it to the end

  uint16_t signatureSize = 0;
  uint16_t offsetForSignatureEncoding = 8;
  uint16_t encodedSignatureSize;

  // generate bootstrapping request signature
  //**************************************//

  uint16_t sig_payload_end_offset = currentOffset;
  // need to subtract TLV_TYPE_AND_LENGTH_SIZE to account for fact that packet header is not included in signature
  uint16_t sig_payload_size = sig_payload_end_offset - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;
  // need to add TLV_TYPE_AND_LENGTH_SIZE to buf_p to account for fact that packet header is not included in signature
  uint8_t *sig_payload_begin = buf_p + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t btstrpRqstSigBuf[SIG_GENERATION_BUF_LENGTH];

  if (!sign_on_basic_client->sec_intf.gen_btstrp_rqst_sig(sign_on_basic_client->KS_pri_p,
                                                          sig_payload_begin, sig_payload_size,
                                                          btstrpRqstSigBuf, SIG_GENERATION_BUF_LENGTH, 
                                                          &encodedSignatureSize)) {
    return CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_SIG;
  }

  //**************************************//

  // add the signature to the packet
  memcpy(buf_p + currentOffset + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE, btstrpRqstSigBuf, encodedSignatureSize);

  buf_p[currentOffset] = SECURE_SIGN_ON_SIGNATURE_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = (uint8_t)encodedSignatureSize;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  currentOffset += encodedSignatureSize;

  // set the first byte of the buffer to be the bootstrapping request tlv type
  buf_p[bootstrappingRequestTlvTypePosition] = SECURE_SIGN_ON_BOOTSTRAPPING_REQUEST_TLV_TYPE;

  // set the second byte of the buffer to be the length of the entire bootstrapping request, excluding the
  // bootstrapping request tlv type and bootstrapping request tlv length (i.e., total buffer size - 2)
  buf_p[bootstrappingRequestTlvLengthPosition] =
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + sign_on_basic_client->device_identifier_len +   // to account for device identifier TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + sign_on_basic_client->device_capabilities_len + // to account for device capabilities TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + sign_on_basic_client->N1_pub_len +              // to account for the N1 pub TLV
      SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + encodedSignatureSize;                               // to account for signature TLV

  *output_len_p = SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE + buf_p[1]; // length of packet header tlv type and length plus rest of packet

  APP_LOG_HEX("Bytes of generated bootstrapping request:", buf_p, *output_len_p);

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_GENERATED_BOOTSTRAPPING_REQUEST;
  return CNSTRCT_BTSTRP_RQST_SUCCESS;
}

enum prcs_btstrp_rqst_rspns_result prcs_btstrp_rqst_rspns(const uint8_t *btstrp_rqst_rspns_buf_p,
    uint16_t btstrp_rqst_rspns_buf_len,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  APP_LOG("Process bootstrapping request response got called.\n");

  // define pointers to data / lengths of data to be copied at the end, after processing is finished,
  // so that no internal state of the sign on basic client object is modified until after the whole
  // message has been processed successfully
  const uint8_t *N2_pub_p;
  uint16_t N2_pub_len;
  const uint8_t *trust_anchor_p;
  uint16_t trust_anchor_len;

  APP_LOG("Length of bootstrapping request tlv block: %d\n", btstrp_rqst_rspns_buf_len);
  APP_LOG_HEX("Contents of bootstrapping request response:", btstrp_rqst_rspns_buf_p, btstrp_rqst_rspns_buf_len);

  enum ParseTlvValueResultCode parseResult = PARSE_TLV_VALUE_SUCCESS;
  uint16_t bootstrappingRequestTlvValueLength;
  uint16_t bootstrappingRequestTlvValueOffset;

  if (parseTlvValue(btstrp_rqst_rspns_buf_p, btstrp_rqst_rspns_buf_len, 
                    SECURE_SIGN_ON_BOOTSTRAPPING_REQUEST_RESPONSE_TLV_TYPE,
                    &bootstrappingRequestTlvValueLength, 
                    &bootstrappingRequestTlvValueOffset) != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of bootstrapping request.");
    return PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_PACKET_HEADER;
  }
  APP_LOG("Bootstrapping request tlv value length: %d\n", bootstrappingRequestTlvValueLength);
  APP_LOG("Bootstrapping request tlv value offset: %d\n", bootstrappingRequestTlvValueOffset);
  APP_LOG_HEX("Value of bootstrapping request tlv block:", btstrp_rqst_rspns_buf_p + bootstrappingRequestTlvValueOffset,
      bootstrappingRequestTlvValueLength);

  const uint8_t *btstrp_rqst_rspns_tlv_val_buf_p = btstrp_rqst_rspns_buf_p + bootstrappingRequestTlvValueOffset;
  uint16_t currentTlvValueLength;
  uint16_t currentTlvValueOffset;

  // first, get the signature and verify it
  // *** //
  
  if (parseTlvValue(btstrp_rqst_rspns_tlv_val_buf_p, bootstrappingRequestTlvValueLength,
                    SECURE_SIGN_ON_SIGNATURE_TLV_TYPE, &currentTlvValueLength, 
                    &currentTlvValueOffset) != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of bootstrapping request response signature.\n");
    return PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_SIG;
  }
  APP_LOG("Bootstrapping request response signature tlv block length: %d\n", currentTlvValueLength);
  APP_LOG("Bootstrapping request response signature tlv value offset: %d\n", currentTlvValueOffset);
  APP_LOG_HEX("Value of signature tlv block:", btstrp_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset,
      currentTlvValueLength);

  // need code to verify signature, return appropriate return code if signature validation fails

  APP_LOG_HEX("Value of signature payload:", btstrp_rqst_rspns_tlv_val_buf_p,
      bootstrappingRequestTlvValueLength - currentTlvValueLength - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE);

  const uint8_t *sig_begin = btstrp_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset;
  uint16_t sig_len = currentTlvValueLength;
  const uint8_t *sig_payload_begin = btstrp_rqst_rspns_tlv_val_buf_p;
  uint16_t sig_payload_len = bootstrappingRequestTlvValueLength - currentTlvValueLength - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  if (!sign_on_basic_client->sec_intf.vrfy_btstrp_rqst_rspns_sig(
          sig_payload_begin, sig_payload_len,
          sig_begin, sig_len,
          sign_on_basic_client->secure_sign_on_code_p,
          sign_on_basic_client->secure_sign_on_code_len)) {
    APP_LOG("Failed to verify bootstrapping request signature.\n");
    return PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE;
  }

  parseTlvValue(btstrp_rqst_rspns_tlv_val_buf_p, bootstrappingRequestTlvValueLength,
      SECURE_SIGN_ON_N2_PUB_TLV_TYPE, &currentTlvValueLength, &currentTlvValueOffset);
  if (parseResult != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of N2 pub.\n");
    return PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_N2_PUB;
  }
  APP_LOG("N2 pub tlv block length: %d\n", currentTlvValueLength);
  APP_LOG("N2 pub tlv value offset: %d\n", currentTlvValueOffset);
  N2_pub_p = btstrp_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset;
  N2_pub_len = currentTlvValueLength;
  APP_LOG_HEX("N2 pub hex from copied pointers:", N2_pub_p, N2_pub_len);
  APP_LOG("Value of N2_pub_len before doing anything else: %d\n", N2_pub_len);

  if (!sign_on_basic_client->sec_intf.gen_kt(N2_pub_p, N2_pub_len,
                                             sign_on_basic_client->N1_pri_p, sign_on_basic_client->N1_pri_len,
                                             sign_on_basic_client->KT_p,
                                             SIGN_ON_BASIC_CLIENT_KT_MAX_LENGTH,
                                             &sign_on_basic_client->KT_len)) {
    APP_LOG("Failed to generate shared secret.\n");
    return PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GENERATE_KT;
  }

  //***************************************************//

  parseTlvValue(btstrp_rqst_rspns_tlv_val_buf_p, bootstrappingRequestTlvValueLength,
      SECURE_SIGN_ON_ANCHOR_CERTIFICATE_TLV_TYPE, &currentTlvValueLength, &currentTlvValueOffset);
  if (parseResult != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of anchor certificate.\n");
    return PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_TRUST_ANCHOR_CERT;
  }
  APP_LOG("Value of N2_pub_len after parseTlvValue for anchor certificate: %d\n", N2_pub_len);
  APP_LOG("Anchor certificate tlv block length: %d\n", currentTlvValueLength);
  APP_LOG("Anchor certificate tlv value offset: %d\n", currentTlvValueOffset);
  trust_anchor_p = btstrp_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset;
  trust_anchor_len = currentTlvValueLength;
  APP_LOG_HEX("Trust anchor from copied pointers:", trust_anchor_p, trust_anchor_len);

//  // now that the entire bootstrapping request respone has been processed successfully, can modify internal state
//  // of sign on client object
  memcpy(sign_on_basic_client->N2_pub_p, N2_pub_p, (size_t) N2_pub_len);
  sign_on_basic_client->N2_pub_len = N2_pub_len;
  memcpy(sign_on_basic_client->trust_anchor_cert_p, trust_anchor_p, (size_t) trust_anchor_len);
  sign_on_basic_client->trust_anchor_cert_len = trust_anchor_len;

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_PROCESSED_BOOTSTRAPPING_REQUEST_RESPONSE;
  return PRCS_BTSTRP_RQST_RSPNS_SUCCESS;
}

enum cnstrct_cert_rqst_result cnstrct_cert_rqst(uint8_t *buf_p, uint16_t buf_len, uint16_t *output_len_p,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  APP_LOG("Construct certificate request got called.\n");

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  if (buf_len < 1) {
    APP_LOG("The buffer passed into construct certificate request was too short.\n");
    return CNSTRCT_CERT_RQST_BUFFER_TOO_SHORT;
  }

  int certificateRequestTlvTypePosition = 0;
  int certificateRequestTlvLengthPosition = 1;

  int currentOffset = 0;
  uint8_t arbitraryValue = 0x03;

  // add TLV_TYPE_AND_LENGTH_SIZE to account for the certificate request tlv type and length;
  // these will be filled in at the end
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t device_identifier_len = sign_on_basic_client->device_identifier_len;
  buf_p[currentOffset] = SECURE_SIGN_ON_DEVICE_IDENTIFIER_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = device_identifier_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->device_identifier_p,
      device_identifier_len * sizeof(uint8_t));
  currentOffset += device_identifier_len;

  APP_LOG_HEX("Value of N1_pub in sign_on_basic_client", sign_on_basic_client->N1_pub_p, sign_on_basic_client->N1_pub_len);

  uint8_t N1_pub_len = sign_on_basic_client->N1_pub_len;
  buf_p[currentOffset] = SECURE_SIGN_ON_N1_PUB_TLV_TYPE;
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
    return CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_N2_PUB_HASH;
  }

  //**************************************//

  uint16_t N2_pub_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = SECURE_SIGN_ON_N2_PUB_DIGEST_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = N2_pub_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, N2_pub_digest_len * sizeof(uint8_t));
  currentOffset += N2_pub_digest_len;

  // need to calculate trust anchor certificate digest here
  //**************************************//

  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->trust_anchor_cert_p,
            sign_on_basic_client->trust_anchor_cert_len, digest_buffer)) {
    return CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_TRUST_ANCHOR_CERT_HASH;
  }

  //**************************************//

  uint16_t trust_anchor_cert_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = SECURE_SIGN_ON_TRUST_ANCHOR_CERTIFICATE_DIGEST_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = trust_anchor_cert_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, trust_anchor_cert_digest_len * sizeof(uint8_t));
  currentOffset += trust_anchor_cert_digest_len;

  // special part of construction: calculate signature over all bytes of certificate request besides the signature
  // tlv block, and append it to the end

  uint16_t signatureSize = 0;
  uint16_t sig_payload_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;
  uint16_t offsetForSignatureEncoding = 8;
  uint16_t encodedSignatureSize;

  // generate signature of bootstrapping request
  //**************************************//

  uint16_t sig_payload_end_offset = currentOffset;
  // need to subtract TLV_TYPE_AND_LENGTH_SIZE to account for fact that packet header is not included in signature
  uint16_t sig_payload_size = sig_payload_end_offset - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;
  // need to add TLV_TYPE_AND_LENGTH_SIZE to buf_p to account for fact that packet header is not included in signature
  uint8_t *sig_payload_begin = buf_p + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t certRqstSigBuf[SIG_GENERATION_BUF_LENGTH];

  if (!sign_on_basic_client->sec_intf.gen_cert_rqst_sig(sign_on_basic_client->KS_pri_p, 
                                                        sig_payload_begin, sig_payload_size,
                                                        certRqstSigBuf, SIG_GENERATION_BUF_LENGTH, 
                                                        &encodedSignatureSize)) {
    return CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_SIG;
  }

  //**************************************//

  // add the signature to the packet
  memcpy(buf_p + currentOffset + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE, certRqstSigBuf, encodedSignatureSize);

  buf_p[currentOffset] = SECURE_SIGN_ON_SIGNATURE_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = (uint8_t)encodedSignatureSize;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  currentOffset += encodedSignatureSize;

  // set the first byte of the buffer to be the certificate request tlv type
  buf_p[certificateRequestTlvTypePosition] = SECURE_SIGN_ON_CERTIFICATE_REQUEST_TLV_TYPE;

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
  return CNSTRCT_CERT_RQST_SUCCESS;
}

enum prcs_cert_rqst_rspns_result prcs_cert_rqst_rspns(const uint8_t *cert_rqst_rspns_buf_p,
    uint16_t cert_rqst_rspns_buf_len,
    struct sign_on_basic_client_t *sign_on_basic_client) {

  // declare pointers to KD pri decrypted and KD pub certificate ahead of time,
  // so that modification of internal state of sign on basic client isn't done until after
  // entire certificate request response message is successfully processed
  const uint8_t *KD_pri_decrypted_p;
  uint16_t KD_pri_decrypted_len;
  const uint8_t *KD_pub_cert_p;
  uint16_t KD_pub_cert_len;

  APP_LOG("Process certificate request response got called.\n");

  enum ParseTlvValueResultCode parseResult = PARSE_TLV_VALUE_SUCCESS;
  uint16_t certificateRequestTlvValueLength;
  uint16_t certificateRequestTlvValueOffset;

  if (parseTlvValue(cert_rqst_rspns_buf_p, cert_rqst_rspns_buf_len, 
                    SECURE_SIGN_ON_CERTIFICATE_REQUEST_RESPONSE_TLV_TYPE,
                    &certificateRequestTlvValueLength, 
                    &certificateRequestTlvValueOffset) != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of certificate request.\n");
    return PRCS_CERT_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_PACKET_HEADER;
  }
  APP_LOG("Certificate request tlv value length: %d\n", certificateRequestTlvValueLength);
  APP_LOG("Certificate request tlv value offset: %d\n", certificateRequestTlvValueOffset);
  APP_LOG_HEX("Value of certificate request tlv block:", cert_rqst_rspns_buf_p + certificateRequestTlvValueOffset,
      certificateRequestTlvValueLength);

  const uint8_t *cert_rqst_rspns_tlv_val_buf_p = cert_rqst_rspns_buf_p + certificateRequestTlvValueOffset;
  uint16_t currentTlvValueLength;
  uint16_t currentTlvValueOffset;

  // verify signature of the certificate request response
  //***************************************************************************//

  if (parseTlvValue(cert_rqst_rspns_tlv_val_buf_p, certificateRequestTlvValueLength,
                    SECURE_SIGN_ON_SIGNATURE_TLV_TYPE, &currentTlvValueLength, 
                    &currentTlvValueOffset) != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of cert request response signature.\n");
    return PRCS_CERT_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_KD_PRI_ENC;
  }
  APP_LOG_HEX("Bytes of signature of cert request response:", cert_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset,
      currentTlvValueLength);

  const uint8_t *sig_begin = cert_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset;
  uint16_t sig_len = currentTlvValueLength;
  const uint8_t *sig_payload_begin = cert_rqst_rspns_tlv_val_buf_p;
  uint16_t sig_payload_len = certificateRequestTlvValueLength - currentTlvValueLength - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  APP_LOG_HEX("Bytes over which cert request response signature was calculated:",
      sig_payload_begin, sig_payload_len);

  if (!sign_on_basic_client->sec_intf.vrfy_cert_rqst_rspns_sig(sig_payload_begin, sig_payload_len,
          sig_begin, sig_len,
          sign_on_basic_client->KT_p,
          sign_on_basic_client->KT_len)) {
    APP_LOG("Failed to verify certificate request signature.\n");
    return PRCS_CERT_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE;
  }

  //***************************************************************************//

  if (parseTlvValue(cert_rqst_rspns_tlv_val_buf_p, certificateRequestTlvValueLength,
                    SECURE_SIGN_ON_KD_PRI_ENCRYPTED_TLV_TYPE, &currentTlvValueLength, 
                    &currentTlvValueOffset) != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of kd pri encrypted.\n");
    return PRCS_CERT_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_KD_PRI_ENC;
  }
  APP_LOG("Kd pri encrypted tlv block length: %d\n", currentTlvValueLength);
  APP_LOG("Kd pri encrypted tlv value offset: %d\n", currentTlvValueOffset);
  const uint8_t *kd_pri_enc_begin = cert_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset;
  uint16_t kd_pri_enc_len = currentTlvValueLength;

  // do decryption of Kd pri here
  //*********************************************************//

  APP_LOG("Doing decryption of Kd pri by Kt.\n");

  uint8_t KD_pri_decrypted_temp_buf[SIGN_ON_BASIC_CLIENT_KD_PRI_MAX_LENGTH];

  if (!sign_on_basic_client->sec_intf.decrypt_kd_pri(
      sign_on_basic_client->KT_p,
      sign_on_basic_client->KT_len,
      kd_pri_enc_begin, kd_pri_enc_len,
      KD_pri_decrypted_temp_buf, &KD_pri_decrypted_len)) {
    return PRCS_CERT_RQST_RSPNS_FAILED_TO_DECRYPT_KD_PRI;
  }



  APP_LOG_HEX("Kd pri decrypted:", KD_pri_decrypted_temp_buf, KD_pri_decrypted_len);

  KD_pri_decrypted_p = KD_pri_decrypted_temp_buf;

  //**********************************************************//

  
  if (parseTlvValue(cert_rqst_rspns_tlv_val_buf_p, certificateRequestTlvValueLength,
                    SECURE_SIGN_ON_KD_PUB_CERTIFICATE_TLV_TYPE, &currentTlvValueLength, 
                    &currentTlvValueOffset) != PARSE_TLV_VALUE_SUCCESS) {
    APP_LOG("Failed to get tlv value of kd pub certificate.\n");
    return PRCS_CERT_RQST_RSPNS_FAILED_TO_GET_TLV_VAL_KD_PUB_CERT;
  }
  APP_LOG("Kd pub certificate tlv block length: %d\n", currentTlvValueLength);
  APP_LOG("Kd pub certificate tlv value offset: %d\n", currentTlvValueOffset);
  KD_pub_cert_p = cert_rqst_rspns_tlv_val_buf_p + currentTlvValueOffset;
  KD_pub_cert_len = currentTlvValueLength;

  // now that entire message has been processed successfully, modify internal state of sign on basic client
  memcpy(sign_on_basic_client->KD_pri_p, KD_pri_decrypted_p, KD_pri_decrypted_len);
  sign_on_basic_client->KD_pri_len = KD_pri_decrypted_len;
  memcpy(sign_on_basic_client->KD_pub_cert_p, KD_pub_cert_p, KD_pub_cert_len);
  sign_on_basic_client->KD_pub_cert_len = KD_pub_cert_len;

  sign_on_basic_client->status = SIGN_ON_BASIC_CLIENT_PROCESSED_CERTIFICATE_REQUEST_RESPONSE;
  return PRCS_CERT_RQST_RSPNS_SUCCESS;
}

enum cnstrct_fin_msg_result cnstrct_fin_msg(uint8_t *buf_p, uint16_t buf_len, uint16_t *output_len_p,
                            struct sign_on_basic_client_t *sign_on_basic_client) {

  APP_LOG("Construct finish message got called.\n");

  uint8_t digest_buffer[SIGN_ON_BASIC_SHA256_HASH_SIZE];

  if (buf_len < 1) {
    APP_LOG("The buffer passed into construct finish message was too short.\n");
    return CNSTRCT_FIN_MSG_BUFFER_TOO_SHORT;
  }

  int finishMessageTlvTypePosition = 0;
  int finishMessageTlvLengthPosition = 1;

  int currentOffset = 0;

  // add TLV_TYPE_AND_LENGTH_SIZE to account for the finish message tlv type and length;
  // these will be filled in at the end
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t device_identifier_len = sign_on_basic_client->device_identifier_len;
  buf_p[currentOffset] = SECURE_SIGN_ON_DEVICE_IDENTIFIER_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = device_identifier_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, sign_on_basic_client->device_identifier_p,
      device_identifier_len * sizeof(uint8_t));
  currentOffset += device_identifier_len;

  uint8_t N1_pub_len = sign_on_basic_client->N1_pub_len;
  buf_p[currentOffset] = SECURE_SIGN_ON_N1_PUB_TLV_TYPE;
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
    return CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_N2_PUB_HASH;
  }

  //**************************************//

  uint16_t N2_pub_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = SECURE_SIGN_ON_N2_PUB_DIGEST_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = N2_pub_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, N2_pub_digest_len * sizeof(uint8_t));
  currentOffset += N2_pub_digest_len;

  // need to calculate trust anchor certificate digest here
  //**************************************//

  if (!sign_on_basic_client->sec_intf.gen_sha256_hash(sign_on_basic_client->trust_anchor_cert_p,
          sign_on_basic_client->trust_anchor_cert_len, digest_buffer)) {
    return CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_TRUST_ANCHOR_CERT_HASH;
  }

  //**************************************//

  uint16_t trust_anchor_cert_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;

  buf_p[currentOffset] = SECURE_SIGN_ON_TRUST_ANCHOR_CERTIFICATE_DIGEST_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = trust_anchor_cert_digest_len;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  memcpy(buf_p + currentOffset, digest_buffer, trust_anchor_cert_digest_len * sizeof(uint8_t));
  currentOffset += trust_anchor_cert_digest_len;

  // special part of construction: calculate signature over all bytes of certificate request besides the signature
  // tlv block, and append it to the end

  uint16_t signatureSize = 0;
  uint16_t sig_payload_digest_len = SIGN_ON_BASIC_SHA256_HASH_SIZE;
  uint16_t offsetForSignatureEncoding = 8;
  uint16_t encodedSignatureSize;

  // generate signature of bootstrapping request
  //**************************************//

  uint16_t sig_payload_end_offset = currentOffset;
  // need to subtract TLV_TYPE_AND_LENGTH_SIZE to account for fact that packet header is not included in signature
  uint16_t sig_payload_size = sig_payload_end_offset - SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;
  // need to add TLV_TYPE_AND_LENGTH_SIZE to buf_p to account for fact that packet header is not included in signature
  uint8_t *sig_payload_begin = buf_p + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE;

  uint8_t certRqstSigBuf[SIG_GENERATION_BUF_LENGTH];

  if (!sign_on_basic_client->sec_intf.gen_fin_msg_sig(sign_on_basic_client->KS_pri_p,
                                                      sig_payload_begin, sig_payload_size,
                                                      certRqstSigBuf, SIG_GENERATION_BUF_LENGTH, 
                                                      &encodedSignatureSize)) {
    return CNSTRCT_FIN_MSG_FAILED_TO_GENERATE_SIG;
  }

  //**************************************//

  // add the signature to the packet
  memcpy(buf_p + currentOffset + SIGN_ON_BASIC_TLV_TYPE_AND_LENGTH_SIZE, certRqstSigBuf, encodedSignatureSize);

  buf_p[currentOffset] = SECURE_SIGN_ON_SIGNATURE_TLV_TYPE;
  currentOffset += SIGN_ON_BASIC_TLV_TYPE_SIZE;
  buf_p[currentOffset] = (uint8_t)encodedSignatureSize;
  currentOffset += SIGN_ON_BASIC_TLV_LENGTH_SIZE;
  currentOffset += encodedSignatureSize;

  // set the first byte of the buffer to be the certificate request tlv type
  buf_p[finishMessageTlvTypePosition] = SECURE_SIGN_ON_FINISH_MESSAGE_TLV_TYPE;

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
  return CNSTRCT_FIN_MSG_SUCCESS;
}