#ifndef NDN_NEIGHBOUR_TABLE_H_
#define NDN_NEIGHBOUR_TABLE_H_

#include "../encoding/block.h"
#include "../encoding/shared-block.h"
#include "../encoding/name.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NDN_IDENTITY_ENTRIES_NUMOF 20
#define NDN_AVAILABLE_ENTRIES_NUMOF 20

typedef struct ndn_available_entry{
    struct ndn_available_entry* prev;
    struct ndn_available_entry* next;
    ndn_block_t avail;
}ndn_available_entry_t;

typedef struct ndn_identity_entry{
    struct ndn_identity_entry* prev;
    struct ndn_identity_entry* next;
    ndn_block_t id;
    ndn_available_entry_t list[NDN_AVAILABLE_ENTRIES_NUMOF];
}ndn_identity_entry_t;

ndn_identity_entry_t* ndn_neighbour_table_identity_get(int pos);

int ndn_neighbour_table_identity_size(void);

ndn_identity_entry_t* ndn_neighbour_table_find_identity(ndn_block_t* identity);

ndn_available_entry_t* ndn_neighbour_table_find_service(ndn_identity_entry_t* identity, ndn_block_t* service);

int ndn_neighbour_table_add_identity(ndn_block_t* identity);

int ndn_neighbour_table_add_service(ndn_identity_entry_t* identity, ndn_block_t* service);

int ndn_neighbour_table_remove_identity(ndn_block_t* identity);

int ndn_neighbour_table_remove_service(ndn_identity_entry_t* identity, ndn_block_t* service);

void ndn_neighbour_table_init(void);


#ifdef __cplusplus
}
#endif

#endif /* NDN_NEIGHBOUR_TABLE_H_ */
/** @} */
