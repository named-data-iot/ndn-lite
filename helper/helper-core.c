#include "helper-core.h"
#include "../face-table.h"
#include "../app.h"
#include "../netif.h"
#include "../l2.h"
#include "../pit.h"
#include "../fib.h"
#include "../cs.h"
#include "../forwarding-strategy.h"
#include "../encoding/ndn-constants.h"
#include "../encoding/name.h"
#include "../encoding/interest.h"
#include "../encoding/data.h"
#include "helper-constants.h"
#include "../msg-type.h"
#include "helper-block.h"
#include "bootstrap.h"
#include "discovery.h"
#include "access.h"
#include "neighbour-table.h"
#define ENABLE_DEBUG 1
#include <debug.h>
#include <thread.h>
#include <timex.h>
#include <xtimer.h>

#define NDN_HELPER_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT * 3 / 4)
#define NDN_HELPER_PRIO              (THREAD_PRIORITY_MAIN - 3)
#define NDN_HELPER_MSG_QUEUE_SIZE    (8U)

//#if ENABLE_DEBUG
//static char _stack[NDN_HELPER_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
//#else
static char _stack[NDN_HELPER_STACK_SIZE];
//#endif

kernel_pid_t ndn_helper_pid = KERNEL_PID_UNDEF;

kernel_pid_t bootstrap_pid = KERNEL_PID_UNDEF;
char* bootstrap_stack = NULL;
//char bootstrap_stack[THREAD_STACKSIZE_MAIN];

kernel_pid_t discovery_pid = KERNEL_PID_UNDEF;
char* discovery_stack = NULL;
//char discovery_stack[THREAD_STACKSIZE_MAIN];

kernel_pid_t access_pid = KERNEL_PID_UNDEF;
char* access_stack = NULL;
//char access_stack[THREAD_STACKSIZE_MAIN];

//below are the tables and tuples NDN_HELPER thread need to maintain
static ndn_bootstrap_t bootstrapTuple;

static int _start_bootstrap(void* ptr)
{
    //ptr pointed to a key pair struct
    
    //assign value
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    bootstrap_stack = (char*)malloc(THREAD_STACKSIZE_MAIN);

    bootstrap_pid = thread_create(bootstrap_stack, THREAD_STACKSIZE_MAIN,
                            THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, ndn_helper_bootstrap, 
                            ptr, "ndn-helper-bootstrap");
    //this thread directly registerd on ndn core thread as a application
    _send.content.ptr = _reply.content.ptr;
    _send.type = NDN_HELPER_BOOTSTRAP_START;

    msg_send_receive(&_send, &_reply, bootstrap_pid);
    ndn_bootstrap_t* buffer = _reply.content.ptr;
    
    //check and store buffer tuple
    if(!buffer) return false;

    bootstrapTuple.certificate.buf = (uint8_t*)malloc(buffer->certificate.len);
    uint8_t* certificate_ptr = (uint8_t*)malloc(buffer->certificate.len);
    memcpy(certificate_ptr, buffer->certificate.buf, buffer->certificate.len);
    bootstrapTuple.certificate.buf = certificate_ptr;
    bootstrapTuple.certificate.len = buffer->certificate.len;

    uint8_t* anchor_ptr = (uint8_t*)malloc(buffer->anchor.len);
    memcpy(anchor_ptr, buffer->anchor.buf, buffer->anchor.len);
    bootstrapTuple.anchor.buf = anchor_ptr;
    bootstrapTuple.anchor.len = buffer->anchor.len;

    uint8_t* home_prefix_ptr = (uint8_t*)malloc(buffer->home_prefix.len);
    memcpy(home_prefix_ptr, buffer->home_prefix.buf, buffer->home_prefix.len);
    bootstrapTuple.home_prefix.buf = home_prefix_ptr;
    bootstrapTuple.home_prefix.len = buffer->home_prefix.len;

    if(bootstrapTuple.certificate.buf){
        DEBUG("ndn-helper: bootstrap success\n");

        ndn_block_t name;
        ndn_data_get_name(&bootstrapTuple.certificate, &name);
        DEBUG("certificate name =  ");
        ndn_name_print(&name);
        putchar('\n');

        return true;
    }
    
    free(bootstrap_stack);
    return false;
}

static int _start_discovery(void)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //this thread directly registerd on ndn core thread as a application
    _send.content.ptr = _reply.content.ptr;

    _send.type = NDN_HELPER_DISCOVERY_START;
    msg_send_receive(&_send, &_reply, discovery_pid);

    DEBUG("ndn-helper: Service Discovery start\n");
    return true;
}

static int _init_access(void)
{
    if(bootstrapTuple.certificate.buf == NULL){
         DEBUG("ndn-helper: haven't bootstrapped yet\n");
         return false;
    }
    access_stack = (char*)malloc(THREAD_STACKSIZE_MAIN);
    access_pid = thread_create(access_stack, THREAD_STACKSIZE_MAIN,
                        THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, ndn_helper_access, 
                        &bootstrapTuple, "ndn-helper-access");

    return true;
}

void* _start_access(msg_t* ptr)
{
    msg_t _send, _reply;
    
    _reply.content.ptr = NULL;

    _send.content.ptr = ptr->content.ptr;
    _send.type = ptr->type;

    msg_send_receive(&_send, &_reply, access_pid);
    //free(access_stack);

    return _reply.content.ptr;
}

static ndn_block_t* _start_discovery_query(void* ptr)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //this thread directly registerd on ndn core thread as a application
    _send.content.ptr = ptr;
    _send.type = NDN_HELPER_DISCOVERY_QUERY;
    
    ndn_app_send_msg_to_app(discovery_pid, NULL, NDN_APP_MSG_TYPE_TERMINATE);
    msg_send_receive(&_send, &_reply, discovery_pid);

    //_reply should contain a ndn_block_t content
    if(_reply.content.ptr){
        ndn_block_t* ptr = _reply.content.ptr;
        return ptr;
    }

    return NULL;
}

static int _set_discovery_prefix(void* ptr)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //ptr should indicate a uri
    _send.content.ptr = ptr;
    _send.type = NDN_HELPER_DISCOVERY_REGISTER_PREFIX;
    msg_send_receive(&_send, &_reply, discovery_pid);

    return true;
}

static int _init_discovery(void)
{
    //pass bootstrapTuple to discovery scenario
    if(bootstrapTuple.certificate.buf == NULL){
         DEBUG("helper: haven't bootstrapped yet\n");
         return false;
    }
    discovery_stack = (char*)malloc(THREAD_STACKSIZE_DEFAULT);
    discovery_pid = thread_create(discovery_stack, THREAD_STACKSIZE_DEFAULT,
                        THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, ndn_helper_discovery, 
                        &bootstrapTuple, "ndn-helper-discovery");
    return true;
}

/* Main event loop for NDN_HELPER */
static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[NDN_HELPER_MSG_QUEUE_SIZE];

    (void)args;
    msg_init_queue(msg_q, NDN_HELPER_MSG_QUEUE_SIZE);

    //TODO: initialize the NDN_HELPER here

    /* start event loop */
    while (1) {
        msg_receive(&msg);

        switch (msg.type) {
            case NDN_HELPER_BOOTSTRAP_START:
                DEBUG("ndn-helper: BOOTSTRAP_START message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                
                if(_start_bootstrap(msg.content.ptr)){
                    reply.content.ptr = &bootstrapTuple;
                }
                else reply.content.ptr = NULL;
                
                msg_reply(&msg, &reply);

                break;

            case NDN_HELPER_DISCOVERY_START:
                DEBUG("ndn-helper: DISCOVERY_START message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                _start_discovery();
                
                reply.content.ptr = NULL; //to invoke the helper caller process
                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_ACCESS_PRODUCER:
                DEBUG("ndn-helper: ACCESS_PRODUCER message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                reply.content.ptr = _start_access(&msg); 

                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_ACCESS_CONSUMER:
                DEBUG("ndn-helper: ACCESS_CONSUMER message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                reply.content.ptr = _start_access(&msg); 
                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_ACCESS_TERMINATE:
                DEBUG("ndn-helper: ACCESS_TERMINATE message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                reply.content.ptr = _start_access(&msg); 
                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_DISCOVERY_QUERY:
                DEBUG("ndn-helper: DISCOVERY_QUERY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                reply.content.ptr = _start_discovery_query(msg.content.ptr);
                
                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_DISCOVERY_INIT:
                DEBUG("ndn-helper: DISCOVERY_INIT message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                               
                _init_discovery();

                reply.content.ptr = NULL; //to invoke the helper caller process
                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_ACCESS_INIT:
                DEBUG("ndn-helper: ACCESS_INIT message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                               
                _init_access();

                reply.content.ptr = NULL; //to invoke the helper caller process
                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_DISCOVERY_REGISTER_PREFIX:
                DEBUG("ndn-helper: DISCOVERY_REGISTER_PREFIX message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                //ptr should point to a string
                _set_discovery_prefix(msg.content.ptr);
                
                reply.content.ptr = NULL; //to invoke the helper caller process
                msg_reply(&msg, &reply);
                break;

            case NDN_HELPER_BOOTSTRAP_INFO:
                DEBUG("ndn-helper: BOOTSTRAP_INFO message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                if(bootstrapTuple.certificate.buf) reply.content.ptr = &bootstrapTuple;
                else reply.content.ptr = NULL;

                msg_reply(&msg, &reply);
                break;
            default:
                break;
        }
    }

    return NULL;
}


kernel_pid_t ndn_helper_init(void)
{
    /* check if thread is already running */
    if (ndn_helper_pid == KERNEL_PID_UNDEF) {
        /* start UDP thread */
        ndn_helper_pid = thread_create(_stack, sizeof(_stack), NDN_HELPER_PRIO,
                                        THREAD_CREATE_STACKTEST, _event_loop, NULL, "ndn-helper");
    }

    ndn_neighbour_table_init();

    return ndn_helper_pid;
}

/** @} */
