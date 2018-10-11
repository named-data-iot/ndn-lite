#ifndef NDN_KEY_H_
#define NDN_KEY_H_

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Type to represent a block of key pair
 * @details This structure does not own the memory pointed by 
 *          @p pub and @p pvt. The user must make sure the 
 *          memory blocks pointed by are still valid as long as 
 *          this structure is in use. Typically a ECDSA key pair 
 *          follows curve secp160r1
 */
typedef struct ndn_keypair {
    const uint8_t* pub;     
    const uint8_t* pvt;          
} ndn_keypair_t;

/**
 * @brief   Type to represent a block of symmetric key
 * @details This structure does not own the memory pointed by 
 *          @p pub and @p pvt. The user must make sure the 
 *          memory blocks pointed by are still valid as long as 
 *          this structure is in use.
 */
typedef struct ndn_key {
    const uint8_t* key;     
    int len;          
} ndn_key_t;

#ifdef __cplusplus
}
#endif

#endif /* NDN_KEY_H_ */
/** @} */
