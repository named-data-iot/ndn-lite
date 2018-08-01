#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include <thread.h>

typedef struct nfl_key_pair_t {
    const uint8_t* pub;     
    const uint8_t* pvt;          
} nfl_key_pair_t;