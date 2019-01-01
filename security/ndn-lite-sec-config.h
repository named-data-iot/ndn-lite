
#ifndef NDN_LITE_SEC_CONFIG_H
#define NDN_LITE_SEC_CONFIG_H

// here you can define the security backend to use for various security
// functionality of ndn-lite. this is useful if you experience issues
// with security library conflicts in the development environment you 
// are using.

// current options: 
//   NDN_LITE_SEC_BACKEND_SHA256_DEFAULT
#define NDN_LITE_SEC_BACKEND_SHA256_DEFAULT

// current options:
//   NDN_LITE_SEC_BACKEND_AES_DEFAULT
#define NDN_LITE_SEC_BACKEND_AES_DEFAULT

// current options:
//   NDN_LITE_SEC_BACKEND_RANDOM_DFEAULT
#define NDN_LITE_SEC_BACKEND_RANDOM_DEFAULT

// current options:
//   NDN_LITE_SEC_BACKEND_ECC_DEFAULT
#define NDN_LITE_SEC_BACKEND_ECC_DEFAULT

// current options:
//   NDN_LITE_SEC_BACKEND_HMAC_DEFAULT
#define NDN_LITE_SEC_BACKEND_HMAC_DEFAULT

#endif // NDN_LITE_SEC_CONFIG_H