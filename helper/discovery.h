#ifndef NDN_DISCOVERY_H_
#define NDN_DISCOVERY_H_


#include "../encoding/block.h"
#include "../encoding/ndn-constants.h"
#include <net/gnrc/pktbuf.h>

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NDN_SUBPREFIX_ENTRIES_NUMOF 20
#define NDN_SERVICE_ENTRIES_NUMOF 10

typedef struct ndn_subprefix_entry{
    struct ndn_subprefix_entry* prev;  
    struct ndn_subprefix_entry* next;
    ndn_block_t sub;
}ndn_subprefix_entry_t;

typedef struct ndn_service_entry{
    struct ndn_service_entry* prev;
    struct ndn_service_entry* next;
    ndn_block_t ser;
}ndn_service_entry_t;

void *ndn_helper_discovery(void* bootstrapTuple);


#ifdef __cplusplus
}
#endif

#endif /* NDN_DISCOVERY_H_ */
/** @} */
