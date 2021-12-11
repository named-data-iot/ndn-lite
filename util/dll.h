/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef UTIL_DLL_H_
#define UTIL_DLL_H_

#include "../forwarder/cs.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * double linked list.
 */
typedef struct dll_entry dll_entry_t;

struct dll_entry{
    /**
     * Corresponding CS entry in nametree.
     */
    ndn_cs_entry_t* cs_entry;

    /**
     * Next entry in list.
     */
    dll_entry_t* next;

    /**
     * Previous entry in list.
     */
    dll_entry_t* prev;

};

void
dll_init(void);

void
dll_insert(ndn_cs_entry_t* entry);

void
dll_remove_first(void);

void
dll_remove_cs_entry(ndn_cs_entry_t* entry);

int
dll_check_all_cs_entry_freshness(void);

int
dll_check_one_cs_entry_freshness(ndn_cs_entry_t* entry);

void
dll_show_all_entries(void);

void
dll_remove_all_entries(void);

/*@}*/

#ifdef __cplusplus
}
#endif

#endif // #define UTIL_DLL_H_
