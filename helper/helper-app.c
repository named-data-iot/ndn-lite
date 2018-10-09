#include <inttypes.h>
#include <sys/types.h>
#include "../encoding/block.h"
#include <thread.h>
#include "helper-core.h"
#include "helper-app.h"
#include "helper-constants.h"
#include <debug.h>


ndn_bootstrap_t* ndn_helper_bootstrap_start(ndn_keypair_t* pair)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_BOOTSTRAP_START;
    msg.content.ptr = pair;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 
    
    //reply message would contain the bootstraptuple
    if(reply.content.ptr) {
        ndn_bootstrap_t* ptr = reply.content.ptr;
        return ptr;
    }

    return NULL;
}


ndn_bootstrap_t* ndn_helper_bootstrap_info(void)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_BOOTSTRAP_INFO;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    if(reply.content.ptr) {
        ndn_bootstrap_t* ptr = reply.content.ptr;
        return ptr;
    }

    return NULL;
}

int ndn_helper_discovery_start(void)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_DISCOVERY_START;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    return true;
}

int ndn_helper_discovery_init(void)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_DISCOVERY_INIT;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    return true;
}

int ndn_helper_discovery_register_prefix(void* ptr)
{  
    //ptr should indicate a uri
    msg_t msg, reply;
    msg.type = NDN_HELPER_DISCOVERY_REGISTER_PREFIX;
    msg.content.ptr = ptr;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    return true;
}

ndn_shared_block_t* ndn_helper_discovery_query(ndn_discovery_t* tuple)
{
    msg_t msg, reply;
    ndn_shared_block_t* ptr;
    msg.type = NDN_HELPER_DISCOVERY_QUERY;
    msg.content.ptr = tuple;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    if(reply.content.ptr) {
        ptr = (ndn_shared_block_t*)reply.content.ptr;
        return ptr;
    }

    return NULL;
}

int ndn_helper_access_init(void)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_ACCESS_INIT;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    return true;
}

uint8_t* ndn_helper_access_producer(ndn_access_t* tuple)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_ACCESS_PRODUCER;
    msg.content.ptr = tuple;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    if(reply.content.ptr == NULL) return NULL;
    uint8_t* ret = reply.content.ptr;
    return ret;
}

uint8_t* ndn_helper_access_consumer(ndn_access_t* tuple)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_ACCESS_CONSUMER;
    msg.content.ptr = tuple;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    if(reply.content.ptr == NULL) return NULL;
    uint8_t* ret = reply.content.ptr;
    return ret;
}

int ndn_helper_access_terminate(void)
{
    msg_t msg, reply;
    msg.type = NDN_HELPER_ACCESS_TERMINATE;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, ndn_helper_pid); 

    return 0;
}