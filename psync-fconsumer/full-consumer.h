#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <ndn-lite.h>
#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"
#include <time.h>
#include <stdlib.h>

#ifndef FULL_CONSUMER_H
#define FULL_CONSUMER_H

typedef struct 
{   
    // Store sequence number for the prefix.
    ndn_name_t prefix;
    uint64_t sequence_number;
} prefixes;

typedef struct
{
// define all the required variables i.e. face, io-service and all
    // ndn_unix_face_t* unix_face;
    ndn_udp_face_t* udp_face;
    ndn_name_t m_syncPrefix;
    ndn_name_t m_syncInterestPrefix;
    ndn_name_t m_iblt;
    ndn_name_t m_syncDataName;
    uint32_t jitter;


    // srand(time(NULL)); //we can use this to create a random number


} full_consumer;

// const ndn::Name& syncPrefix,
//                    ndn::Face& face,
//                    const UpdateCallback& onUpdate,
//                    ndn::time::milliseconds syncInterestLifetime


void init_full_consumer (const char* syncPrefix, ndn_udp_face_t* face, 
                         void (*onUpdate)(void*));

void send_sync_interet();

void on_sync_data(); 

void stop (); 

#endif 
