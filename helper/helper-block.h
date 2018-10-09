#ifndef HELPER_BLOCK_H_
#define HELPER_BLOCK_H_

#include <inttypes.h>
#include <sys/types.h>
#include "../encoding/block.h"
#include "../encoding/key.h"
#include <thread.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Type to represent a bootstrap tuple
 * @details m_cert represent the allocated cert in bootstrapping
 *          home_prefix represent the name TLV encoded home prefix
 */
typedef struct ndn_bootstrap {
    ndn_block_t certificate;     
    ndn_block_t anchor;
    ndn_block_t home_prefix;        
} ndn_bootstrap_t;

/**
 * @brief   Type to represent a discovery tuple
 * @details This structure does not own the memory pointed by @p identity 
 *          and @p service. The user must make sure the memory blocks pointed 
 *          are still valid as long as this structure is in use.
 */
typedef struct ndn_discovery{
    ndn_block_t* identity;     
    ndn_block_t* service;       
}ndn_discovery_t;

/**
 * @brief   Type to represent a access tuple
 *          @p ace represent ECDSA key pair used in access control
 *          @p opt represent optional parameter in block, can be NULL 
 *          no optional parameter
 * @details This structure does not own the memory pointed by @p ace 
 *          and @p opt. The user must make sure the memory blocks 
 *          pointed are still valid as long as this structure is in use.
 */
typedef struct ndn_access {
    ndn_keypair_t* ace;
    ndn_block_t* opt;
}ndn_access_t;

#ifdef __cplusplus
}
#endif

#endif /* HELPER_BLOCK_H_ */
/** @} */