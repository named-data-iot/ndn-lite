/*

This is a psync full consumer implementation 
Details: https://redmine.named-data.net/issues/4987

*/

#include "full-consumer.h"

void 
init_full_consumer(char* syncPrefix, ndn_udp_face_t* face, 
                         void (*onUpdate)(void*))
{
    full_consumer* consumer;
    consumer->udp_face = face;
    
    ndn_name_from_string(&consumer->m_syncPrefix, syncPrefix, sizeof(syncPrefix));
    ndn_name_print(&consumer->m_syncPrefix);

    //  char controller_prefix_string[] = "/ndn/AC";
    //  ndn_name_t controller_prefix;
    //  ndn_name_from_string(&controller_prefix, controller_prefix_string, sizeof(controller_prefix_string));


    // int
// ndn_name_from_string(ndn_name_t* name, const char* string, uint32_t size);
    // have to convert char to ndn_name and assign it to m_iblt
    // consumer->m_iblt = "x%9Cc%60%18%05%A3%60%F8%00%00%02%D0%00%01";






//   : m_face(face)
//  , m_scheduler(m_face.getIoService())
//  , m_syncPrefix(syncPrefix)
//  , m_iblt("x%9Cc%60%18%05%A3%60%F8%00%00%02%D0%00%01") //empty IBF
//  , m_onUpdate(onUpdate)
//  , m_syncInterestLifetime(syncInterestLifetime)
//  , m_rng(ndn::random::getRandomNumberEngine())
//  , m_rangeUniformRandom(100, 500)
// {
//   int jitter = m_syncInterestLifetime.count() * .20;
//   m_jitter = std::uniform_int_distribution<>(-jitter, jitter);

//   sendSyncInterest();
// }

}

void 
send_sync_interet() 
{
  
}

void
on_sync_data()
{
  
}

void 
stop () 
{
    // stop running fetcher
}