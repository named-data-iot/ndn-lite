#ifndef NDN_BOOTSTRAP_H_
#define NDN_BOOTSTRAP_H_

#include "../encoding/block.h"
#include "../encoding/ndn-constants.h"
#include <net/gnrc/pktbuf.h>

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void* ndn_helper_bootstrap(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* NDN_BOOTSTRAP_H_ */
/** @} */
