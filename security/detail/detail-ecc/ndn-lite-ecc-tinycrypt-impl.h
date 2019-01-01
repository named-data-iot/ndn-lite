
#ifndef NDN_LITE_ECC_TINYCRYPT_H
#define NDN_LITE_ECC_TINYCRYPT_H

#include "../../ndn-lite-crypto-key.h"

int ndn_lite_ecc_key_shared_secret_tinycrypt(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                                             uint8_t curve_type, uint8_t* output, 
                                             uint32_t output_size);

int ndn_lite_ecc_key_make_key_tinycrypt(ndn_ecc_pub_t* ecc_pub, ndn_ecc_prv_t* ecc_prv,
                                        uint8_t curve_type, uint32_t key_id);

#endif // NDN_LITE_ECC_TINYCRYPT_H