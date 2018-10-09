#ifndef NDN_SECURITY_H_
#define NDN_SECURITY_H_

#include "encoding/name.h"
#include "encoding/metainfo.h"

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int ndn_security_make_signature(uint8_t pri_key[32], ndn_block_t* seg, uint8_t* buf_sig);

int ndn_security_make_hmac_signature(uint8_t* key_ptr, ndn_block_t* seg, uint8_t* buf_sig);

#ifdef __cplusplus
}
#endif

#endif /* NDN_SECURITY_H_ */
/** @} */
