/*
 * Copyright (C) 2019 Xinyu Ma, Yu Guan
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name-tree.h"
#include <stdio.h>

typedef struct ndn_nametree{
  size_t capacity;
  size_t size;
  nametree_entry_t pool[NDN_PIT_MAX_SIZE];
}ndn_nametree_t;

static ndn_nametree_t nametree;


void nametree_refresh(int num)
{
    nametree.pool[num].left_child = nametree.pool[num].pit_id = nametree.pool[num].fib_id = NDN_NAMETREE_INVALID_ID;
    nametree.pool[num].right_bro = nametree.pool[0].right_bro;
    nametree.pool[0].right_bro = num;
}

int clean(int num)
{
    int ret = 0;
    if (num == NDN_NAMETREE_INVALID_ID) return NDN_NAMETREE_INVALID_ID;
    nametree.pool[num].left_child = clean(nametree.pool[num].left_child);
    nametree.pool[num].right_bro = clean(nametree.pool[num].right_bro);
    if (nametree.pool[num].fib_id == NDN_NAMETREE_INVALID_ID &&
        nametree.pool[num].pit_id == NDN_NAMETREE_INVALID_ID &&
        nametree.pool[num].left_child == NDN_NAMETREE_INVALID_ID) {
        ret = nametree.pool[num].right_bro;
        nametree_refresh(num);
        return ret;
    }
    return num;
}

void
ndn_nametree_cleanup()
{
    nametree.pool[0].left_child = clean(nametree.pool[0].left_child);
}

void
ndn_nametree_init()
{
    //all free entries are linked as right_bro of nametree.pool[0], the root of the tree.
    for (int i = 0; i < NDN_PIT_MAX_SIZE; ++i) {
        nametree.pool[i].left_child = nametree.pool[i].pit_id = nametree.pool[i].fib_id = NDN_NAMETREE_INVALID_ID;
        nametree.pool[i].right_bro = i + 1;
    }
    nametree.pool[NDN_PIT_MAX_SIZE - 1].right_bro = NDN_NAMETREE_INVALID_ID;
}

//-1: name1 < name2
//0: name1 == name2
//1: name1 > name2
int component_match(uint8_t *name1 , uint8_t *name2 , size_t len)
{
    for (int i = 0; i < len; ++i) {
        if (name1[i] < name2[i]) return -1;
        if (name1[i] > name2[i]) return 1;
    }
    return 0;
}

// return NDN_NAMETREE_INVALID_ID if node creation failure(because no free entries), else return the index of newly created node.
int create_node(uint8_t name[], size_t len)
{
    int output = nametree.pool[0].right_bro;
    if (output == NDN_NAMETREE_INVALID_ID) return NDN_NAMETREE_INVALID_ID;
    nametree.pool[0].right_bro = nametree.pool[output].right_bro;
    nametree.pool[output].left_child = nametree.pool[output].pit_id = nametree.pool[output].fib_id = nametree.pool[output].right_bro = NDN_NAMETREE_INVALID_ID;
    for (int i = 0; i < len; ++i)
        nametree.pool[output].val[i] = name[i];
    return output;
}

nametree_entry_t*
ndn_nametree_find_or_insert_try(uint8_t name[], size_t len)
{
    int now_node, last_node, father = 0 , offset = 0 , tmp , new_node_number;
    size_t component_len;
    if (len < 2) return NULL;
    if (name[1] < 253) offset = 2; else offset = 4;
    while (offset < len) {
        component_len = name[offset + 1] + 2;
        now_node = nametree.pool[father].left_child;
        last_node = NDN_NAMETREE_INVALID_ID;
        tmp = -2;
        while (now_node != NDN_NAMETREE_INVALID_ID) {
            tmp = component_match(name+offset, nametree.pool[now_node].val , component_len);
            if (tmp <= 0) break;
            last_node = now_node;
            now_node = nametree.pool[now_node].right_bro;
        }
        if (tmp != 0 && last_node == NDN_NAMETREE_INVALID_ID) {
            new_node_number = create_node(name + offset , component_len);
            if (new_node_number == NDN_NAMETREE_INVALID_ID) return NULL;
            nametree.pool[father].left_child = new_node_number;
            nametree.pool[new_node_number].right_bro = now_node;
            offset += component_len;
            father = new_node_number;
            continue;
        }
        if (tmp != 0) {
            new_node_number = create_node(name + offset , component_len);
            if (new_node_number == NDN_NAMETREE_INVALID_ID) return NULL;
            nametree.pool[last_node].right_bro = new_node_number;
            nametree.pool[new_node_number].right_bro = now_node;
            offset += component_len;
            father = new_node_number;
            continue;
        }
        offset += component_len;
        father = now_node;
    }
    return &nametree.pool[father];
}

nametree_entry_t*
ndn_nametree_find_or_insert(uint8_t name[], size_t len)
{
    nametree_entry_t* p = ndn_nametree_find_or_insert_try(name , len);
    if (p == NULL) {
        ndn_nametree_cleanup();
        p = ndn_nametree_find_or_insert_try(name , len);
    }
    return p;
}

nametree_entry_t*
ndn_nametree_prefix_match(uint8_t name[], size_t len , int type)
{
    int now_node, last_node = NDN_NAMETREE_INVALID_ID , father = 0 , offset = 0 , component_len , tmp;
    if (len < 2) return NULL;
    if (name[1] < 253) offset = 2; else offset = 4;
    while (offset < len) {
        component_len = name[offset + 1] + 2;
        now_node = nametree.pool[father].left_child;
        tmp = -2;
        while (now_node != NDN_NAMETREE_INVALID_ID) {
            tmp = component_match(name+offset,nametree.pool[now_node].val , component_len);
            if (tmp <= 0) break;
            now_node = nametree.pool[now_node].right_bro;
        }
        if (tmp == 0) {
            if (nametree.pool[now_node].fib_id != NDN_NAMETREE_INVALID_ID && type == NDN_FIB_TYPE) last_node = now_node;
            if (nametree.pool[now_node].pit_id != NDN_NAMETREE_INVALID_ID && type == NDN_PIT_TYPE) last_node = now_node;
        } else break;
        offset += component_len;
        father = now_node;
    }
    if (last_node == NDN_NAMETREE_INVALID_ID) return NULL; else return &nametree.pool[last_node];
}