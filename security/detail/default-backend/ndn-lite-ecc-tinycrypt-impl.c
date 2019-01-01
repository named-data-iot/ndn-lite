#include "ndn-lite-ecc-tinycrypt-impl.h"
#include "../../../ndn-error-code.h"
#include "../../../ndn-constants.h"
#include "../../../ndn-enums.h"
#include "../sec-lib/tinycrypt/tc_ecc_dh.h"
#include "../sec-lib/tinycrypt/tc_constants.h"
#include "ndn-lite-rng-tinycrypt-impl.h"

int
ndn_lite_ecc_key_shared_secret_tinycrypt(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                                             uint8_t curve_type, uint8_t* output,
                                             uint32_t output_size)
{
  if (output_size < 24)
    return NDN_SEC_NOT_ENABLED_FEATURE;
  tc_uECC_Curve curve;
  switch(curve_type) {
    case NDN_ECDSA_CURVE_SECP256R1:
      curve = tc_uECC_secp256r1();
      break;
    default:
      // TODO: support other ECDSA with micro-ecc
      return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  }
  int r = tc_uECC_shared_secret(ecc_pub->key_value, ecc_prv->key_value, output, curve);
  if (r != TC_CRYPTO_SUCCESS) return NDN_SEC_CRYPTO_ALGO_FAILURE;
  return NDN_SUCCESS;
}

int ndn_lite_ecc_key_make_key_tinycrypt(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                                        uint8_t curve_type, uint32_t key_id)
{
  tc_uECC_Curve curve;
  switch(curve_type) {
    case NDN_ECDSA_CURVE_SECP256R1:
      curve = tc_uECC_secp256r1();
      break;
    default:
      // TODO: support other ECDSA with micro-ecc
      return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  }
  int r = tc_uECC_make_key(ecc_pub->key_value, ecc_prv->key_value, curve);
  if (r != TC_CRYPTO_SUCCESS)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  ecc_pub->key_id = key_id;
  ecc_prv->key_id = key_id;
  ecc_pub->key_size = tc_uECC_curve_public_key_size(curve);
  ecc_prv->key_size = tc_uECC_curve_private_key_size(curve);
  return NDN_SUCCESS;
}
