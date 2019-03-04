/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sign-on-basic-client-nrf-sdk-ble.h"

#include "../../../encode/tlv.h"
#include "../secure-sign-on/sign-on-basic-client.h"
#include "../../../adaptation/ndn-nrf-ble-adaptation/nrf-sdk-ble-consts.h"
#include "../../../ndn-error-code.h"
#include "sdk_common.h"

#define TEMP_BUF_LENGTH 500

static struct sign_on_basic_client_t m_sign_on_basic_client;
static sign_on_basic_client_nrf_sdk_ble_t sign_on_basic_client_nrf_sdk_ble;
void (*m_on_sign_on_completed)(int result_code); //**< Callback for sign on completion set by sign_on_basic_client_ble_init_result. */

sign_on_basic_client_nrf_sdk_ble_t *
get_sign_on_basic_client_nrf_sdk_ble_instance() {
  return &sign_on_basic_client_nrf_sdk_ble;
}

void m_on_transport_connected(uint32_t conn_handle) {

}

void m_on_transport_disconnected() {

}

void m_on_transport_hvn_tx_complete(uint32_t conn_handle) {

}

void m_on_transport_adv_stopped() {

}

void m_on_transport_mtu_rqst(uint32_t conn_handle) {
  // after the central is done negotiating its MTU with us, we send our bootstrapping request

  if (m_sign_on_basic_client.status == SIGN_ON_BASIC_CLIENT_GENERATED_FINISH_MESSAGE) {
    return;
  }

  ret_code_t err_code;

  uint32_t bootstrappingRequestBufLength = TEMP_BUF_LENGTH;
  uint8_t bootstrappingRequestBuf[TEMP_BUF_LENGTH];
  uint32_t bootstrappingRequestLength = 0;

  int cnstrct_result = cnstrct_btstrp_rqst(bootstrappingRequestBuf, bootstrappingRequestBufLength, &bootstrappingRequestLength,
      &m_sign_on_basic_client);
  if (cnstrct_result != NDN_SUCCESS) {
    m_on_sign_on_completed(cnstrct_result);
    return;
  }

  if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_send(bootstrappingRequestBuf, 
      bootstrappingRequestLength) != NRF_BLE_OP_SUCCESS) {
    m_on_sign_on_completed(SIGN_ON_BASIC_CLIENT_BLE_FAILED_TO_SEND_BOOTSTRAPPING_REQUEST);
  }
}

void m_on_recvd_data_callback(const uint8_t *payload, uint32_t payload_len) {

  if (m_sign_on_basic_client.status == SIGN_ON_BASIC_CLIENT_GENERATED_FINISH_MESSAGE) {
    return;
  }

  if (payload_len < 1) {
    return;
  }

  if (payload[0] == TLV_SSP_BOOTSTRAPPING_REQUEST_RESPONSE) {

    int result = prcs_btstrp_rqst_rspns(payload, payload_len, &m_sign_on_basic_client);
    if (result != NDN_SUCCESS) {
      return;
    }

    ret_code_t err_code;

    uint32_t certificateRequestBufLength = TEMP_BUF_LENGTH;
    uint8_t certificateRequestBuf[TEMP_BUF_LENGTH];
    uint32_t certificateRequestLength = 0;

    int cnstrct_result = cnstrct_cert_rqst(certificateRequestBuf, certificateRequestBufLength, &certificateRequestLength,
        &m_sign_on_basic_client);
    if (cnstrct_result != NDN_SUCCESS) {
      m_on_sign_on_completed(cnstrct_result);
      return;
    }

    if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_send(certificateRequestBuf, certificateRequestLength) != NRF_BLE_OP_SUCCESS) {
      m_on_sign_on_completed(SIGN_ON_BASIC_CLIENT_BLE_FAILED_TO_SEND_CERTIFICATE_REQUEST);
    }

  } else if (payload[0] == TLV_SSP_CERTIFICATE_REQUEST_RESPONSE) {

    int result = prcs_cert_rqst_rspns(payload, payload_len, &m_sign_on_basic_client);
    if (result != NDN_SUCCESS) {
      return;
    }

    uint32_t finishMessageBufLength = TEMP_BUF_LENGTH;
    uint8_t finishMessageBuf[finishMessageBufLength];
    uint32_t finishMessageLength;

    int cnstrct_result = cnstrct_fin_msg(finishMessageBuf, finishMessageBufLength, &finishMessageLength,
      &m_sign_on_basic_client);
    if (cnstrct_result != NDN_SUCCESS) {
      m_on_sign_on_completed(cnstrct_result);
      return;
    }

    if (nrf_sdk_ble_ndn_lite_ble_unicast_transport_send(finishMessageBuf, finishMessageBufLength) != NRF_BLE_OP_SUCCESS) {
      m_on_sign_on_completed(SIGN_ON_BASIC_CLIENT_BLE_FAILED_TO_SEND_FINISH_MESSAGE);
    }

    sign_on_basic_client_nrf_sdk_ble.KD_pri_p = m_sign_on_basic_client.KD_pri_p;
    sign_on_basic_client_nrf_sdk_ble.KD_pri_len = m_sign_on_basic_client.KD_pri_len;
    sign_on_basic_client_nrf_sdk_ble.KD_pub_cert_p = m_sign_on_basic_client.KD_pub_cert_p;
    sign_on_basic_client_nrf_sdk_ble.KD_pub_cert_len = m_sign_on_basic_client.KD_pub_cert_len;
    sign_on_basic_client_nrf_sdk_ble.trust_anchor_cert_p = m_sign_on_basic_client.trust_anchor_cert_p;
    sign_on_basic_client_nrf_sdk_ble.trust_anchor_cert_len = m_sign_on_basic_client.trust_anchor_cert_len;

    m_on_sign_on_completed(NDN_SUCCESS);

  }
}

int sign_on_basic_client_nrf_sdk_ble_construct(uint8_t variant,
                                   const uint8_t *device_identifier_p, uint32_t device_identifier_len,
                                   const uint8_t *device_capabilities_p, uint32_t device_capabilities_len,
                                   const uint8_t *secure_sign_on_code_p,
                                   const uint8_t *KS_pub_p, uint32_t KS_pub_len,
                                   const uint8_t *KS_pri_p, uint32_t KS_pri_len,
                                   void (*on_sign_on_completed)(int result_code)) {

  m_on_sign_on_completed = on_sign_on_completed;
  
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_init();
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_observer_t observer;
  observer.on_connected = m_on_transport_connected;
  observer.on_disconnected = m_on_transport_disconnected;
  observer.on_mtu_rqst = m_on_transport_mtu_rqst;
  observer.on_hvn_tx_complete = m_on_transport_hvn_tx_complete;
  observer.on_recvd_data = m_on_recvd_data_callback;
  observer.on_adv_stopped = m_on_transport_adv_stopped;
  nrf_sdk_ble_ndn_lite_ble_unicast_transport_add_observer(observer);

  int sign_on_client_init_result = sign_on_basic_client_init(variant,
                                                         &m_sign_on_basic_client,
                                                         device_identifier_p, device_identifier_len,
                                                         device_capabilities_p, device_capabilities_len,
                                                         secure_sign_on_code_p,
                                                         KS_pub_p, KS_pub_len,
                                                         KS_pri_p, KS_pri_len);

  if (sign_on_client_init_result != NDN_SUCCESS) {
    return NDN_SIGN_ON_BASIC_CLIENT_NRF_SDK_BLE_CONSTRUCT_FAILED_TO_INITIALIZE_SIGN_ON_BASIC_CLIENT;
  }
  
  return NDN_SUCCESS;

}
