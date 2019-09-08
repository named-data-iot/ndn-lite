/*

This is a psync full consumer implementation 
Details: https://redmine.named-data.net/issues/4987

*/

#include "full-consumer.h"

void error_reporting(int val)
{
    if(val != 0) 
        { printf("%s %d \n", "Something wrong happened. Error code: ", val); }
    else 
        { printf ("%s %d\n", "message code: ", val); }

}
void 
init_full_consumer(const char* syncPrefix, ndn_udp_face_t* face, 
                         void (*onUpdate)(void*))
{
    
    full_consumer *consumer = (full_consumer*)malloc(sizeof(full_consumer));
    consumer->udp_face = face;
    error_reporting(ndn_name_from_string(&consumer->m_syncPrefix, syncPrefix, strlen(syncPrefix)));
    // ndn_name_print(&consumer->m_syncPrefix);
    
    // construct empty IBLT
    const char* ibf = "/x\x9C""c""\x60\x18\x05\xA3\x60\xF8\x00\x00\x02\xD0\x00\x01";
    error_reporting(ndn_name_from_string(&consumer->m_iblt, ibf, strlen(ibf)));
    
    send_sync_interet(consumer);

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
on_sync_data()
{
  printf("%s\n", "someting on data");
}

void 
timeout()
{
  printf("%s\n", "someting on timeout");
}
// 
void 
send_sync_interet(full_consumer* consumer) 
{
  ndn_name_append_name(&consumer->m_syncPrefix, &consumer->m_iblt);
  ndn_name_print(&consumer->m_syncPrefix);
  uint8_t buf[4096];
  bool running;

  ndn_interest_t interest;
  ndn_encoder_t encoder;
  encoder_init(&encoder, buf, 4096);
  ndn_name_tlv_encode(&encoder, &consumer->m_syncPrefix);
  
  ndn_forwarder_add_route(&consumer->udp_face->intf, buf, encoder.offset);
  
  ndn_interest_from_name(&interest, &consumer->m_syncPrefix);

  ndn_interest_set_MustBeFresh(&interest, true);
  ndn_interest_set_CanBePrefix(&interest, true);
  interest.nonce = random();
  encoder_init(&encoder, buf, 4096);
  ndn_interest_tlv_encode(&encoder, &interest);
  ndn_forwarder_express_interest(encoder.output_value, encoder.offset, on_sync_data, timeout, NULL);

}

void 
stop () 
{
    // stop running fetcher
}