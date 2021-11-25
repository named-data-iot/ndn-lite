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
#define ENABLE_NDN_LOG_DEBUG 0
#define ENABLE_NDN_LOG_ERROR 1
#include "dll.h"
#include "../forwarder/forwarder.h"
#include "../util/logger.h"
#include "../util/uniform-time.h"

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

void dll_remove_cs_entry(ndn_cs_entry_t* entry){
  NDN_LOG_DEBUG("dll_remove_cs_entry called\n");
  if (entry == NULL){
    NDN_LOG_DEBUG("No CS entry to remove\n");
    return;
  }

  if (head == NULL){
    NDN_LOG_DEBUG("No CS entry in list\n");
    return;
  }

  if (head->next == head){
    if (head->cs_entry == entry)
      dll_remove_first();
    else
      NDN_LOG_DEBUG("CS entry not in dll found");
    return;
  }

  const ndn_forwarder_t* forwarder = ndn_forwarder_get();
  dll_entry_t* cur = head;

  if (head->cs_entry == entry){
    NDN_LOG_DEBUG("CS entry found at head %p\n", head);

    head = head->next;
    head->prev = cur->prev;

    free(cur->cs_entry->content);
    ndn_cs_remove_entry(forwarder->cs, cur->cs_entry);

    cur->next = NULL;
    cur->prev = NULL;
    cur->cs_entry = NULL;

    free(cur);
    cur = NULL;

    return;
  }

  cur = cur->next;

  while (cur != head)
  {
    if (cur->cs_entry == entry){
      NDN_LOG_DEBUG("CS entry found %p\n", cur);

      cur->next->prev = cur->prev;
      cur->prev->next = cur->next;

      free(cur->cs_entry->content);
      ndn_cs_remove_entry(forwarder->cs, cur->cs_entry);

      cur->next = NULL;
      cur->prev = NULL;
      cur->cs_entry = NULL;

      free(cur);
      cur = NULL;

      return;
    }
    cur = cur->next;
  }
  NDN_LOG_DEBUG("CS entry not in dll found\n");

}

int dll_check_all_cs_entry_freshness(void){
  int counter = 0;

  if (head == NULL){
    NDN_LOG_DEBUG("no entry in dll found\n");
    return counter;
  }

  dll_entry_t* tmp = head->next;
  ndn_time_ms_t now = ndn_time_now_ms();

  if (head->cs_entry->fresh_until <= now){
    NDN_LOG_DEBUG("expired entry in CS head detected\n");
    counter++;

    if (head->next == head){
      NDN_LOG_DEBUG("only one entry in dll\n");

      dll_remove_cs_entry(head->cs_entry);

      return counter;
    }
    dll_remove_cs_entry(head->cs_entry);
  }

  while (tmp != head){
    if (tmp->cs_entry->fresh_until <= now){
      NDN_LOG_DEBUG("expired entry in CS entry detected\n");
      counter++;

      tmp = tmp->next;

      dll_remove_cs_entry(tmp->prev->cs_entry);
    } else tmp = tmp->next;
  }
  return counter;
}

int dll_check_one_cs_entry_freshness(ndn_cs_entry_t* entry){
  ndn_time_ms_t now = ndn_time_now_ms();
  NDN_LOG_DEBUG("check one entry for freshness\n");

  if (entry == NULL){
    NDN_LOG_DEBUG("No valid CS entry chosen\n");
    return NDN_INVALID_POINTER;
  }

  if (entry->fresh_until <= now){
    NDN_LOG_DEBUG("CS entry is not fresh\n");
    return -1;
  } else return NDN_SUCCESS;

}

void dll_show_all_entries(void){
  if (head == NULL){
    NDN_LOG_DEBUG("The dll is empty\n");
    return;
  }

  NDN_LOG_DEBUG("Showing full dll starting with oldest entry:\n");
  dll_entry_t* tmp = head->next;
  printf("%p\n", head);
  while (tmp != head){
    printf("%p\n", tmp);
    tmp = tmp->next;
  }
}

void dll_remove_all_entries(void){
  if (head == NULL){
    NDN_LOG_DEBUG("The dll is already empty\n");
    return;
  }

  NDN_LOG_DEBUG("Removing all dll and CS entries\n");
  while (head != NULL){
    dll_remove_first();
  }
}
