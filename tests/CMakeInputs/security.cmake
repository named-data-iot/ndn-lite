set(DIR_SECURITY "${DIR_NDN_LITE}/security")
set(DIR_DEFAULT_BACKEND "${DIR_SECURITY}/default-backend/")
set(DIR_MICRO_ECC "${DIR_DEFAULT_BACKEND}/sec-lib/micro-ecc")
set(DIR_TINYCRYPT "${DIR_DEFAULT_BACKEND}/sec-lib/tinycrypt")
target_sources(ndn-lite PUBLIC
  ${DIR_SECURITY}/ndn-lite-aes.h
  ${DIR_SECURITY}/ndn-lite-ecc.h
  ${DIR_SECURITY}/ndn-lite-hmac.h
  ${DIR_SECURITY}/ndn-lite-rng.h
  ${DIR_SECURITY}/ndn-lite-sec-config.h
  ${DIR_SECURITY}/ndn-lite-sec-utils.h
  ${DIR_SECURITY}/ndn-lite-sha.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_SECURITY}/ndn-lite-aes.c
  ${DIR_SECURITY}/ndn-lite-ecc.c
  ${DIR_SECURITY}/ndn-lite-hmac.c
  ${DIR_SECURITY}/ndn-lite-rng.c
  ${DIR_SECURITY}/ndn-lite-sec-config.c
  ${DIR_SECURITY}/ndn-lite-sec-utils.c
  ${DIR_SECURITY}/ndn-lite-sha.c
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-aes-impl.h
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-aes-impl.c
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-ecc-impl.h
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-ecc-impl.c
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-rng-impl.h
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-rng-impl.c
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-hmac-impl.h
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-hmac-impl.c
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-sha-impl.h
  ${DIR_DEFAULT_BACKEND}/ndn-lite-default-sha-impl.c
  ${DIR_MICRO_ECC}/uECC.c
  ${DIR_MICRO_ECC}/uECC.h
  ${DIR_TINYCRYPT}/tc_aes_decrypt.c
  ${DIR_TINYCRYPT}/tc_aes_encrypt.c
  ${DIR_TINYCRYPT}/tc_aes.h
  ${DIR_TINYCRYPT}/tc_cbc_mode.h
  ${DIR_TINYCRYPT}/tc_cbc_mode.c
  ${DIR_TINYCRYPT}/tc_ccm_mode.h
  ${DIR_TINYCRYPT}/tc_ccm_mode.c
  ${DIR_TINYCRYPT}/tc_cmac_mode.h
  ${DIR_TINYCRYPT}/tc_cmac_mode.c
  ${DIR_TINYCRYPT}/tc_constants.h
  ${DIR_TINYCRYPT}/tc_ctr_mode.c
  ${DIR_TINYCRYPT}/tc_ctr_mode.h
  ${DIR_TINYCRYPT}/tc_ctr_prng.c
  ${DIR_TINYCRYPT}/tc_ctr_prng.h
  ${DIR_TINYCRYPT}/tc_ecc_dh.c
  ${DIR_TINYCRYPT}/tc_ecc_dh.h
  ${DIR_TINYCRYPT}/tc_ecc_dsa.c
  ${DIR_TINYCRYPT}/tc_ecc_dsa.h
  ${DIR_TINYCRYPT}/tc_ecc_platform_specific.c
  ${DIR_TINYCRYPT}/tc_ecc_platform_specific.h
  ${DIR_TINYCRYPT}/tc_ecc.c
  ${DIR_TINYCRYPT}/tc_ecc.h
  ${DIR_TINYCRYPT}/tc_hmac_prng.c
  ${DIR_TINYCRYPT}/tc_hmac_prng.h
  ${DIR_TINYCRYPT}/tc_hmac.c
  ${DIR_TINYCRYPT}/tc_hmac.h
  ${DIR_TINYCRYPT}/tc_sha256.c
  ${DIR_TINYCRYPT}/tc_sha256.h
  ${DIR_TINYCRYPT}/tc_utils.c
  ${DIR_TINYCRYPT}/tc_utils.h
)
unset(DIR_SECURITY)
unset(DIR_DEFAULT_BACKEND)
unset(DIR_MICRO_ECC)
unset(DIR_TINYCRYPT)
