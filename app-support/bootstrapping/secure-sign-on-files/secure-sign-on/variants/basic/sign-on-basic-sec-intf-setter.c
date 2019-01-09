/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "sign-on-basic-sec-intf-setter.h"

#include "sign-on-basic-consts.h"

#include "../../../../../../ndn-error-code.h"

#include "variants/ecc_256/sign-on-basic-ecc-256-sec.h"

#include <stdio.h>

int sign_on_basic_set_sec_intf(uint8_t variant, struct sign_on_basic_client_t *sign_on_basic_client) {
  switch (variant) {
    case SIGN_ON_BASIC_VARIANT_ECC_256: {

      sign_on_basic_client->sec_intf.gen_sha256_hash = sign_on_basic_ecc_256_gen_sha256_hash;
      sign_on_basic_client->sec_intf.gen_n1_keypair = sign_on_basic_ecc_256_gen_n1_keypair;
      sign_on_basic_client->sec_intf.gen_kt = sign_on_basic_ecc_256_gen_kt;
      sign_on_basic_client->sec_intf.gen_btstrp_rqst_sig = sign_on_basic_ecc_256_gen_btstrp_rqst_sig;
      sign_on_basic_client->sec_intf.get_btstrp_rqst_sig_len = sign_on_basic_ecc_256_get_btstrp_rqst_sig_len;
      sign_on_basic_client->sec_intf.vrfy_btstrp_rqst_rspns_sig = sign_on_basic_ecc_256_vrfy_btstrp_rqst_rspns_sig;
      sign_on_basic_client->sec_intf.gen_cert_rqst_sig = sign_on_basic_ecc_256_gen_cert_rqst_sig;
      sign_on_basic_client->sec_intf.get_cert_rqst_sig_len = sign_on_basic_ecc_256_get_cert_rqst_sig_len;
      sign_on_basic_client->sec_intf.vrfy_cert_rqst_rspns_sig = sign_on_basic_ecc_256_vrfy_cert_rqst_rspns_sig;
      sign_on_basic_client->sec_intf.decrypt_kd_pri = sign_on_basic_ecc_256_decrypt_kd_pri;
      sign_on_basic_client->sec_intf.gen_fin_msg_sig = sign_on_basic_ecc_256_gen_fin_msg_sig;
      sign_on_basic_client->sec_intf.get_fin_msg_sig_len = sign_on_basic_ecc_256_get_fin_msg_sig_len;

      break;
    }
    default:
      return NDN_SIGN_ON_BASIC_CLIENT_INIT_FAILED_UNRECOGNIZED_VARIANT;
  }

  return NDN_SUCCESS;
}