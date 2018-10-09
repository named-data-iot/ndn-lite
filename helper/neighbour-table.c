#include "neighbour-table.h"
#include <debug.h>

#include <stdlib.h>
#include <string.h>

static ndn_identity_entry_t _identity_table[NDN_IDENTITY_ENTRIES_NUMOF];


ndn_identity_entry_t* ndn_neighbour_table_identity_get(int pos)
{
    if ((pos < 0) || (!_identity_table[pos].id.buf)) return NULL;
    return &_identity_table[pos];
}

int ndn_neighbour_table_identity_size(void)
{
    int size = 0;
    for (int i = 0; i < NDN_IDENTITY_ENTRIES_NUMOF; ++i) {
        if (_identity_table[i].id.buf) {
            size++;
        }
    }
    return size;
}

ndn_identity_entry_t* ndn_neighbour_table_find_identity(ndn_block_t* identity)
{
    for (int i = 0; i < NDN_IDENTITY_ENTRIES_NUMOF; ++i) {
        int r = ndn_name_compare_block(&_identity_table[i].id, identity);     
        if (r == 0) {
            return &_identity_table[i];
        }
    }
    return NULL;
}

ndn_available_entry_t* ndn_neighbour_table_find_service(ndn_identity_entry_t* identity, ndn_block_t* service)
{
    for (int i = 0; i < NDN_AVAILABLE_ENTRIES_NUMOF; ++i) {
        int r = ndn_name_compare_block(&identity->list[i].avail, service);     
        if (r == 0) {
            return &identity->list[i];
        }
    }
    return NULL;
}

int ndn_neighbour_table_add_identity(ndn_block_t* identity)
{
    /* compare the name TLV encoded identity to id table */
    ndn_identity_entry_t* entry = NULL;
    for (int j = 0; j < NDN_IDENTITY_ENTRIES_NUMOF; ++j) {   
        int r = ndn_name_compare_block(&_identity_table[j].id, identity);     
        if (r == 0) {
            DEBUG("ndn-helper: neighbour identity entry already exists\n");
            return -1;
        }

        if ((!entry) && (_identity_table[j].id.buf == NULL)) {
            entry = &_identity_table[j];
            break;
        }   
    }

    if (!entry) {
        DEBUG("ndn-helper: cannot allocate neighbour identity\n");
        return -1;
    }

    /* add identity */
    entry->prev = entry->next = NULL;
    entry->id = *identity;
    DEBUG("ndn-helper: add neighbour identity entry\n");
    return 0;
}

int ndn_neighbour_table_add_service(ndn_identity_entry_t* identity, ndn_block_t* service)
{
    /* compare the name TLV encoded service to id table */
    ndn_available_entry_t* entry = NULL;
    for (int j = 0; j < NDN_AVAILABLE_ENTRIES_NUMOF; ++j) {   
        int r = ndn_name_compare_block(&identity->list[j].avail, service);     
        if (r == 0) {
            DEBUG("ndn-helper: neighbour service entry already exists\n");
            return -1;
        }

        if ((!entry) && (identity->list[j].avail.buf == NULL)) {
            entry = &identity->list[j];
            break;
        }
    }

    if (!entry) {
        DEBUG("ndn-helper: cannot allocate neighbour identity\n");
        return -1;
    }

    entry->prev = entry->next = NULL;
    entry->avail = *service;
    return 0;
}

int ndn_neighbour_table_remove_identity(ndn_block_t* identity)
{
    ndn_identity_entry_t *entry = ndn_neighbour_table_find_identity(identity);
    if (entry) {
        DEBUG("ndn-helper: remove identity entry, together with available services\n");
        memset(entry, 0, sizeof(*entry));
        ndn_block_t init = {NULL, 0};
        entry->id = init;
        entry->next = NULL;
        
        /* initialize the avaiable table */
        for (int j = 0; j < NDN_AVAILABLE_ENTRIES_NUMOF; ++j) {
            entry->list[j].avail = init;
            entry->list[j].next = NULL;
        }
        return 0;
    }

    return -1;
}

int ndn_neighbour_table_remove_service(ndn_identity_entry_t* identity, ndn_block_t* service)
{
    ndn_available_entry_t *entry = ndn_neighbour_table_find_service(identity, service);
    if (entry) {
        DEBUG("ndn-helper: remove service entry, keep identity record\n");
        memset(entry, 0, sizeof(*entry));
        ndn_block_t init = {NULL, 0};
        entry->avail = init;
        entry->next = NULL;
        return 0;
    }

    return -1;
}

void ndn_neighbour_table_init(void)
{
    for (int i = 0; i < NDN_IDENTITY_ENTRIES_NUMOF; ++i) {
        ndn_block_t init = {NULL, 0};
        _identity_table[i].id = init;
        _identity_table[i].next = NULL;
        
        /* initialize the avaiable table */
        for (int j = 0; j < NDN_AVAILABLE_ENTRIES_NUMOF; ++j) {
            _identity_table[i].list[j].avail = init;
            _identity_table[i].list[j].next = NULL;
        }
    }
}

/** @} */
