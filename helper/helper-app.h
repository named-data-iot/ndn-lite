#include <inttypes.h>
#include <sys/types.h>
#include "../encoding/block.h"
#include "../encoding/shared-block.h"
#include "helper-msg.h"
#include "helper-block.h"
#include "discovery.h"
#include "access.h"

#ifndef HELPER_APP_H_
#define HELPER_APP_H_

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief  Sends an bootstrap request to helper thread
 *
 * @param[in]  key pair struct
 *
 * @return Bootstrap Tuple ptr, if success.
 * @return NULL, if out of memory during sending.
 * @return NULL, if timeout
 */
ndn_bootstrap_t* ndn_helper_bootstrap_start(ndn_keypair_t* pair);

/**
 * @brief  Extract bootstrap request from helper thread
 *
 * @return Bootstrap Tuple ptr, if success.
 * @return NULL, if haven't bootstrapped yet.
 */
ndn_bootstrap_t* ndn_helper_bootstrap_info(void);

/**
 * @brief  Sends a discovery start request to helper thread.
 *         This function will collect available subprefixes 
 *         and aggregate them into serveral services. Call 
 *         this function before init() and set() will incur 
 *         errors.
 *
 * @return 0, if success.
 * @return -1, if error.
 */
int ndn_helper_discovery_start(void);

/**
 * @brief  Sends a access producer side request to helper 
 *         thread. This function use identity based 
 *         scheme. Call this funtion before init() will 
 *         incur errors.  
 *         Caller must make copy
 * 
 * @param[in]  Access tuple ptr
 * 
 * @return Producer Seed ptr, if success.
 * @return NULL, if timeout 
 * @return NULL, if error.
 */
uint8_t* ndn_helper_access_producer(ndn_access_t* tuple);

/**
 * @brief  Sends a access consumer side request to helper 
 *         thread. This function use identity based 
 *         scheme. Call this funtion before init() will 
 *         incur errors.   
 *         Caller must make copy
 * 
 * @param[in]  Access tuple ptr
 * 
 * @return Producer Seed ptr, if success.
 * @return NULL, if timeout 
 * @return NULL, if error.
 */
uint8_t* ndn_helper_access_consumer(ndn_access_t* tuple);

/**
 * @brief  Sends a setting discovery subprefix request to 
 *         helper thread. Call this funtion before init() 
 *         will incur errors. 
 *
 * @param[in] Subprefix ptr in (char*) 
 * 
 * @return 0, if success.
 * @return -1, if error.
 */
int ndn_helper_discovery_register_prefix(void* ptr);

/**
 * @brief  Sends a discovery init request to helper thread. 
 *         helper will create a thread for discovery thread. 
 *         init process includes initializing the identity
 *         table and subprefix table.
 * 
 * @return 0, if success.
 * @return -1, if error.
 */
int ndn_helper_discovery_init(void);

/**
 * @brief  Sends a access init request to helper thread. 
 *         helper will create a thread for access control 
 *         thread. 
 * 
 * @return 0, if success.
 * @return -1, if error.
 */
int ndn_helper_access_init(void);

int ndn_helper_access_terminate(void);

/**
 * @brief  Sends a discovery query request to helper thread. 
 *         Call this funtion before init() will incur errors. 
 *         Caller release the return shared block
 * 
 * @param[in] Discovery tuple ptr 
 * 
 * @return Metadata ptr, if success.
 * @return NULL, if timeout.
 * @return NULL, if error.
 */
ndn_shared_block_t* ndn_helper_discovery_query(ndn_discovery_t* tuple);


#ifdef __cplusplus
}
#endif

#endif /* HELPER_APP_H_ */
/** @} */
