#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include <thread.h>

//all these stuff are read only
typedef struct nfl_key_pair_t {
    const uint8_t* pub;     
    const uint8_t* pvt;          
} nfl_key_pair_t;

typedef struct nfl_bootstrap_tuple_t {
    ndn_block_t* m_cert;     
    ndn_block_t* anchor_cert;
    ndn_block_t* home_prefix;        
} nfl_bootstrap_tuple_t;
