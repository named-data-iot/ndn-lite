
#ifndef NDN_LITE_SEC_CONFIG_H
#define NDN_LITE_SEC_CONFIG_H

// here you can define the security backend to use for various security
// functionality of ndn-lite. this is useful if you experience issues
// with security library conflicts in the development environment you 
// are using.

// current options: 
//   NDN_LITE_SEC_BACKEND_SIGN_VERIFY_DEFAULT
//   NDN_LITE_SEC_BACKEND_SIGN_VERIFY_NRF_CRYPTO
#define NDN_LITE_SEC_BACKEND_SIGN_VERIFY_NRF_CRYPTO

// current options:
//   NDN_LITE_SEC_BACKEND_AES_DEFAULT
//   NDN_LITE_SEC_BACKEND_AES_NRF_CRYPTO
#define NDN_LITE_SEC_BACKEND_AES_NRF_CRYPTO

// current options:
//   NDN_LITE_SEC_BACKEND_RANDOM_DFEAULT
//   NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO
#define NDN_LITE_SEC_BACKEND_RANDOM_NRF_CRYPTO

#endif // NDN_LITE_SEC_CONFIG_H