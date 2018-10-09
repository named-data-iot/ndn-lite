#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include "../app.h"
#include "../ndn.h"
#include "../encoding/name.h"
#include "../encoding/interest.h"
#include "../encoding/ndn-constants.h"
#include "../ndn.h"
#include "../encoding/data.h"
#include "../msg-type.h"
#include "neighbour-table.h"
#include "crypto/ciphers.h"
#include "uECC.h"
#include <string.h>
#include "../encoding/block.h"
#include "../encoding/shared-block.h"
#include "discovery.h"
#include "helper-block.h"
#include "helper-constants.h"

#define DEBUG(...) printf(__VA_ARGS__)
#define _MSG_QUEUE_SIZE    (8U)

static ndn_app_t* handle = NULL;

static uint8_t ecc_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

/*
static uint8_t ecc_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

static ndn_subprefix_entry_t _subprefix_table[NDN_SUBPREFIX_ENTRIES_NUMOF];
static ndn_service_entry_t _service_table[NDN_SERVICE_ENTRIES_NUMOF];

static ndn_block_t home_prefix;
static ndn_block_t host_name;
static msg_t from_helper, to_helper;

static int broadcast_timeout(ndn_block_t* interest);

void ndn_discovery_service_table_init(void)
{
    for (int i = 0; i < NDN_SERVICE_ENTRIES_NUMOF; ++i) {
        ndn_block_t init = {NULL, 0};
        _service_table[i].ser = init;
        _service_table[i].next = NULL;
    }
}

void ndn_discovery_subprefix_table_init(void)
{
    for (int i = 0; i < NDN_SUBPREFIX_ENTRIES_NUMOF; ++i) {
        ndn_block_t init = {NULL, 0};
        _subprefix_table[i].sub = init;
        _subprefix_table[i].next = NULL;
    }
}

static int ndn_discovery_collect(ndn_block_t* interest){

    /* skip home prefix and "servicediscovery" */
    int inter_len = ndn_name_get_size_from_block(interest);
    int home_len = ndn_name_get_size_from_block(&home_prefix);// home prefix should be name TLV
    int num = inter_len - home_len - 3; // number of available services

    ndn_block_t identity;
    ndn_name_get_component_from_block(interest, home_len + 1, &identity);

    /* check the identity table, first we need construct id a name TLV */
    ndn_shared_block_t* identity_name = ndn_name_move_from_comp(&identity);

    ndn_identity_entry_t* entry = ndn_neighbour_table_find_identity(&identity_name->block);
    if (entry != NULL){
        DEBUG("ndn-helper-discovery: received identity exist\n");

        /* recollect service */
        for (int i = 0; i < num; ++i){ //within the service list
            ndn_block_t service;
            ndn_name_get_component_from_block(interest, home_len + 3 + i, &service);

            ndn_shared_block_t* service_name = ndn_name_move_from_comp(&service);
            ndn_neighbour_table_add_service(entry, &service_name->block);
        }
    }

    else{ 
        DEBUG("ndn-helper-discovery: add received identity to table\n");

        /* add identity */
        ndn_neighbour_table_add_identity(&identity_name->block);

        entry = ndn_neighbour_table_find_identity(&identity_name->block);

        /* add services */
        for (int i = 0; i < num; ++i){ //within the service list
            ndn_block_t service;
            ndn_name_get_component_from_block(interest, home_len + 3 + i, &service);

            ndn_shared_block_t* service_name = ndn_name_move_from_comp(&service);
            ndn_neighbour_table_add_service(entry, &service_name->block);
        }
    }
    
    return 0;
}


static int ndn_discovery_add_subprefix(const char* sub)

{
    ndn_subprefix_entry_t* entry = NULL;
    
    ndn_shared_block_t* sn = ndn_name_from_uri(sub, strlen(sub));

    for (int i = 0; i < NDN_SUBPREFIX_ENTRIES_NUMOF; ++i){
        int r = ndn_name_compare_block(&_subprefix_table[i].sub, &sn->block);
        if (r == 0) {
            DEBUG("ndn-helper-discovery: subprefix entry already exists\n");
            return -1;
        }

        if ((!entry) && (_subprefix_table[i].sub.buf == NULL)) {
            entry = &_subprefix_table[i];
            break;
        }
    }

    if (!entry) {
        DEBUG("ndn-helper-discovery: cannot allocate subprefix entry\n");
        return -1;
    }

    entry->prev = entry->next = NULL;
    entry->sub = sn->block;

    return 0;
}

static int ndn_discovery_make_service_list(void){
    
    ndn_block_t comp;
    /* extract the first part */

    for (int i = 0; _subprefix_table[i].sub.buf != NULL; ++i) {

        ndn_service_entry_t* entry = NULL;
        ndn_name_get_component_from_block(&_subprefix_table[i].sub, 0, &comp);
        
        /* after this comp is freed */
        ndn_shared_block_t* comp_name = ndn_name_move_from_comp(&comp);

        for (int j = 0; j < NDN_SERVICE_ENTRIES_NUMOF; ++j) {

            int r = ndn_name_compare_block(&_service_table[j].ser, &comp_name->block);     
            if (r == 0) {
                break;
            }

            if ((!entry) && (_service_table[j].ser.buf == NULL)) {
                entry = &_service_table[j];
                break;
            }
        }

        if (!entry) continue;
        else{
            entry->prev = entry->next = NULL;
            entry->ser = comp_name->block;
        }
  
    }

    return 0;
}
            

/* how about we assume less than 10 services ? */
/* but we must use linked list to store the subprefix */
static int ndn_discovery_service_check(ndn_block_t* tocheck){
    
    int r = 1; 
    for (int i = 0; i < NDN_SERVICE_ENTRIES_NUMOF && _service_table[i].ser.buf; ++i) {
        r = ndn_name_compare_block(&_service_table[i].ser, tocheck);     
        if (r == 0) {
            DEBUG("ndn-helper-discovery: find proper service name\n");
            return 0;// success
        }
    }
    
    DEBUG("ndn-helper-discovery: no such service name\n");
    return -1;
}

/* please pass the service block in name TLV */

static int ndn_discovery_service_extract(ndn_block_t* service, ndn_block_t ptr[]){
    
    int r = ndn_discovery_service_check(service);
    if (r != 0) return -1;
 
    /* now we do have such service */
    for (int i = 0; i < NDN_SUBPREFIX_ENTRIES_NUMOF && _subprefix_table[i].sub.buf; ++i) {
        
        /* extract the first component to check */
        ndn_block_t first;
        ndn_name_get_component_from_block(&_subprefix_table[i].sub, 0, &first);

        /* construct name TLV from block */
        ndn_shared_block_t* first_name = ndn_name_move_from_comp(&first);

        /* compare it with service */
        r = ndn_name_compare_block(&first_name->block, service);
        if (r == 0) {
            DEBUG("ndn-helper-discovery: find one subprefix = ");
            ndn_name_print(&_subprefix_table[i].sub);
            putchar('\n');
            ptr[i] = _subprefix_table[i].sub;
        }
        
    }

    return 0;//success
}

static ndn_shared_block_t* ndn_discovery_make_broadcast(ndn_block_t* id){
    const char* uri = "/servicelist";
    ndn_shared_block_t* sl = ndn_name_from_uri(uri, strlen(uri));

    for (int i = 0; i < NDN_SERVICE_ENTRIES_NUMOF && _service_table[i].ser.buf; ++i) {
        sl = ndn_name_append_from_name(&sl->block, &_service_table[i].ser); 
    }
    
    sl = ndn_name_append_from_name(id, &sl->block);

    return sl; 
}

static int on_query(ndn_block_t* interest)
{
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): cannot get name from interest"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): service query received, name =",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    /* get wanted service name */
    int home_len = ndn_name_get_size_from_block(&home_prefix);
    ndn_block_t service;
    ndn_name_get_component_from_block(&in, home_len + 1, &service);

    /* reencode it into name TLV */
    ndn_shared_block_t* service_name = ndn_name_move_from_comp(&service);

    /* check and extract */
    ndn_block_t ptr[NDN_SUBPREFIX_ENTRIES_NUMOF];
    for (int i = 0; i < NDN_SUBPREFIX_ENTRIES_NUMOF; ++i) ptr[i].buf = NULL;

    int r = ndn_discovery_service_extract(&service_name->block, ptr);
    if(r == -1){
        DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): no such service available, name =",
            handle->id);
        ndn_name_print(&service_name->block);
        putchar('\n');
        return NDN_APP_CONTINUE;
    }

    /* found match */
    int len = 0;
    for(int i = 0; i < NDN_SUBPREFIX_ENTRIES_NUMOF && ptr[i].buf; ++i) len += ptr[i].len;

    uint8_t* buffer = (uint8_t*)malloc(len);
    uint8_t* start = buffer;    
    for(int i = 0; i < NDN_SUBPREFIX_ENTRIES_NUMOF && ptr[i].buf; ++i){
        memcpy(start, ptr[i].buf, ptr[i].len); start += ptr[i].len;
    }
    ndn_block_t content = { buffer, len};

    putchar('\n');
    ndn_name_print(&content);
    putchar('\n');putchar('\n');

    /* send back data */
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };
    ndn_shared_block_t* back = ndn_name_append_uint8(&in, 2);
    ndn_shared_block_t* data =
        ndn_data_create(&back->block, &meta, &content,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL, ecc_key_pri, sizeof(ecc_key_pri));

    if (data == NULL) {
        DEBUG("ndn-helper-discovery (pid=%" PRIkernel_pid "): cannot compose Query Response\n",
               handle->id);
        ndn_shared_block_release(data);
        return NDN_APP_ERROR;
    }

    DEBUG("ndn-helper-discovery (pid=%" PRIkernel_pid "): send Query Response to NDN thread, name =",
           handle->id);
    ndn_name_print(&back->block);
    putchar('\n');
    ndn_shared_block_release(back);

    /* pass the packet */
    if (ndn_app_put_data(handle, data) != 0) {
        DEBUG("ndn-helper-discovery (pid=%" PRIkernel_pid "): cannot put Query Response\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    free(buffer);
    return NDN_APP_CONTINUE;
}

static int on_query_response(ndn_block_t* interest, ndn_block_t* data){
    
    (void)interest;
    ndn_block_t name, content;
    ndn_data_get_name(data, &name);
    ndn_data_get_content(data, &content);
    DEBUG("ndn-helper-discovery (pid=%" PRIkernel_pid "): Query Response received, name =",
           handle->id);
    ndn_name_print(&name);
    putchar('\n');
    
    ndn_shared_block_t* ptr = ndn_shared_block_create_by_move(&content);

    to_helper.content.ptr = ptr;
    msg_reply(&from_helper, &to_helper); //send response to ndn

    return NDN_APP_CONTINUE;
}

static int on_query_timeout(ndn_block_t* interest){

    ndn_block_t name;
    int r = ndn_interest_get_name(interest, &name);
    assert(r == 0);

    DEBUG("ndn-helper-discovery (pid=%" PRIkernel_pid "): Query timeout, name =",
           handle->id);
    ndn_name_print(&name);
    putchar('\n');

    to_helper.content.ptr = NULL;
    msg_reply(&from_helper, &to_helper); //send response to ndn

    return NDN_APP_CONTINUE;
}

static int broadcast_timeout(ndn_block_t* interest)
{
    ndn_block_t name;
    ndn_interest_get_name(interest, &name);
    uint32_t lifetime = 60000; // 1 minute
    ndn_app_express_interest(handle, &name, NULL, lifetime, NULL, broadcast_timeout);

    DEBUG("ndn-helper-discovery (pid=%" PRIkernel_pid "): broadcast name = ",
           handle->id);
    ndn_name_print(&name);
    putchar('\n');

    return NDN_APP_CONTINUE; 
}

static int on_broadcast(ndn_block_t* interest)
{
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): cannot get name from interest"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): broadcast received, name =",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    ndn_discovery_collect(&in);

    return NDN_APP_CONTINUE;
}

void *ndn_helper_discovery(void* bootstrapTuple)
{
    /* extract home prefix and identity name from bootstrapTuple */
    ndn_bootstrap_t* tuple = bootstrapTuple;

    home_prefix = tuple->home_prefix;
    ndn_name_print(&home_prefix); putchar('\n');


    ndn_block_t cert_name;
    ndn_data_get_name(&tuple->certificate, &cert_name);
    ndn_name_print(&cert_name); putchar('\n');


    int home_len = ndn_name_get_size_from_block(&home_prefix);
    ndn_block_t host;
    ndn_name_get_component_from_block(&cert_name, home_len, &host);
                    
    /* construct it in name TLV */    
    ndn_shared_block_t* host_sp = ndn_name_move_from_comp(&host);
    host_name = host_sp->block;


    /* initiate parameters */
    handle = ndn_app_create();
    if (handle == NULL) {
        DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return NULL;
    }

    ndn_discovery_subprefix_table_init();
    ndn_discovery_service_table_init();

    DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): init\n", thread_getpid());

    /* discovery event loop */
    msg_t msg_q[_MSG_QUEUE_SIZE];
    msg_init_queue(msg_q, _MSG_QUEUE_SIZE);

    //TODO: initialize the NDN here

    /* start event loop */
    while (1) {
        msg_receive(&from_helper);

        switch (from_helper.type) {
            case NDN_HELPER_DISCOVERY_START:
                DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): discovery broadcast\n",
                        thread_getpid());

                /* make service prefix list*/
                ndn_discovery_make_service_list();

                /* register broadcast filter */
                const char* prefix = "/servicediscovery";
                ndn_shared_block_t* spn = ndn_name_from_uri(prefix, strlen(prefix));
                spn = ndn_name_append_from_name(&home_prefix, &spn->block);
                ndn_app_register_prefix(handle, spn, on_broadcast);
                
                /* register unicast query filter */
                for (int j = 0; j < NDN_SERVICE_ENTRIES_NUMOF && _service_table[j].ser.buf; ++j) {
                    ndn_shared_block_t* toquery = ndn_name_append_from_name(&home_prefix, &host_name);
                    toquery = ndn_name_append_from_name(&toquery->block, &_service_table[j].ser);
                    const char* query = "/query";
                    ndn_shared_block_t* str = ndn_name_from_uri(query, strlen(query));
                    toquery = ndn_name_append_from_name(&toquery->block, &str->block);
                    ndn_app_register_prefix(handle, toquery, on_query);
                }

                /* make and broadcast interest */
                ndn_shared_block_t* tosend = ndn_name_append_from_name(&spn->block, &host_name);
                tosend = ndn_discovery_make_broadcast(&tosend->block);

                uint32_t lifetime = 60000; // 1 minute
                ndn_app_express_interest(handle, &tosend->block, NULL, lifetime, NULL, broadcast_timeout);
                DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): broadcast, name =", handle->id);
                ndn_name_print(&tosend->block);
                putchar('\n');
                                
                to_helper.content.ptr = NULL; //to invoke the ndn caller process
                msg_reply(&from_helper, &to_helper);//this should be the last operation in while loop 
            
                xtimer_sleep(20);
                ndn_app_run(handle); 

                /* discovery thread will stall here until a terminate instruction from NDN sent in */
                
                break;

            case NDN_HELPER_DISCOVERY_REGISTER_PREFIX:
                DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): register service prefix\n",
                        thread_getpid());

                //ptr should point to a string
                ndn_discovery_add_subprefix(from_helper.content.ptr);
                
                to_helper.content.ptr = NULL; //to invoke the ndn caller process
                msg_reply(&from_helper, &to_helper);
                break;

            case NDN_HELPER_DISCOVERY_QUERY:
                DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): start discovery query\n",
                        thread_getpid());

                /* msg should contain a <id, service> tuple */
                lifetime = 8000; // 2 seconds
                ndn_discovery_t* tuple = from_helper.content.ptr;                    
                ndn_shared_block_t* toquery = ndn_name_append_from_name(&home_prefix,
                                             tuple->identity);
                toquery = ndn_name_append_from_name(&toquery->block,
                                             tuple->service);
                const char* query = "/query";
                ndn_shared_block_t* str = ndn_name_from_uri(query, strlen(query));
                toquery = ndn_name_append_from_name(&toquery->block, &str->block);
                toquery = ndn_name_append_from_name(&toquery->block, &host_name);

                ndn_app_express_interest(handle, &toquery->block, NULL, lifetime, on_query_response, on_query_timeout);
                DEBUG("ndn-helper-discovery(pid=%" PRIkernel_pid "): query, name =", handle->id);
                ndn_name_print(&toquery->block);
                putchar('\n');
                ndn_app_run(handle);

                break;

            default:
                break;
        }

    }

    return NULL;
}

