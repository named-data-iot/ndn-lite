#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include "nfl-constant.h"
#include "nfl-block.h"
/*
    this function is used for ndn-riot app send ipc message to NFL, to start bootstrap 
*/

/*static int nfl_start_bootstrap(uint8_t BKpub[64], uint8_t BKpvt[32]);*/



#ifndef NFL_APP_H_
#define NFL_APP_H_

#ifdef __cplusplus
extern "C" {
#endif

int nfl_start_bootstrap(uint8_t BKpub[64], uint8_t BKpvt[32]);

//caller must contain the memeory of tuple
int nfl_extract_bootstrap_tuple(nfl_bootstrap_tuple_t* tuple);



#ifdef __cplusplus
}
#endif

#endif /* NFL_APP_H_ */
/** @} */
