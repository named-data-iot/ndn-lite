/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */
#define ENABLE_NDN_LOG_INFO 0
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1
#include "dll.h"
#include "../forwarder/forwarder.h"
#include "../util/logger.h"

static dll_entry_t* head;

void dll_init(void){
  head = NULL;
}

void dll_insert(ndn_cs_entry_t* entry){
  NDN_LOG_DEBUG("dll_insert called\n");
  if (entry == NULL){
    NDN_LOG_DEBUG("The cs-entry is empty\n");
    return;
  }

  dll_entry_t* new_entry = malloc(sizeof(dll_entry_t));

  if (head == NULL){
    NDN_LOG_DEBUG("The linked list is currently empty, inserting first entry\n");

    head = new_entry;
    head->next = head;
    head->prev = head;
    head->cs_entry = entry;

    printf("Inserted first entry %p\n", (void*) head);

    NDN_LOG_DEBUG("First entry is inserted successfully\n");
    return;
  }

  dll_entry_t* last = head->prev;

  new_entry->next = head;
  new_entry->prev = last;
  new_entry->cs_entry = entry;

  head->prev = new_entry;
  last->next = new_entry;

  printf("Inserted entry %p with next: %p prev: %p\n", (void*) new_entry, (void*) new_entry->next, (void*) new_entry->prev);

}

void dll_remove_first(void){
  NDN_LOG_DEBUG("dll_remove_first called\n");
  if (head == NULL){
    NDN_LOG_DEBUG("The linked list is empty\n");
    return;
  }

  // check if only one entry in dll
  if (head->next == head){
    NDN_LOG_DEBUG("only one entry in dll, removing that\n");

    free(head->cs_entry->content);

    const ndn_forwarder_t* forwarder = ndn_forwarder_get();
    ndn_cs_remove_entry(forwarder->cs, head->cs_entry);

    head->next = NULL;
    head->prev = NULL;
    head->cs_entry = NULL;

    free(head);

    head = NULL;

    return;
  }

  dll_entry_t* tmp = head;
  dll_entry_t* last = head->prev;

  head = head->next;
  head->prev = last;
  last->next = head;

  NDN_LOG_DEBUG("head pointer after shifting: %p next: %p prev: %p\n", (void*) head, (void*) head->next, (void*) head->prev);
  free(tmp->cs_entry->content);

  const ndn_forwarder_t* forwarder = ndn_forwarder_get();
  ndn_cs_remove_entry(forwarder->cs, tmp->cs_entry);
  
  tmp->next = NULL;
  tmp->prev = NULL;
  tmp->cs_entry = NULL;

  free(tmp);

  tmp = NULL;
}