#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "crypto/ciphers.h"
#include "crypto/modes/cbc.h"
#include "uECC.h"
#include <hashes/sha256.h>
#include "../app.h"
#include "../ndn.h"
#include "../encoding/name.h"
#include "../encoding/interest.h"
#include "../encoding/data.h"
#include "helper-constants.h"

#include "../encoding/block.h"
#include "../encoding/shared-block.h"
#include "access.h"
#include "../encoding/ndn-constants.h"
#include "helper-block.h"

#define DPRINT(...) printf(__VA_ARGS__)
#define _MSG_QUEUE_SIZE    (8U)

static ndn_app_t* handle = NULL;


static uint8_t anchor_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

static uint8_t com_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static uint8_t ace_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static uint8_t ace_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

static uint8_t TEST_1_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};


static ndn_block_t home_prefix;
static ndn_block_t identity;
static msg_t to_helper, from_helper;
static unsigned char acehmac_pro[32] = {0};
static unsigned char acehmac_con[32] = {0};
static uint8_t producer_key[32] = {0};

static int on_producer_ace(ndn_block_t* interest, ndn_block_t* data)
{

    (void)interest;

    ndn_block_t name;
    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);

    DPRINT("producer-ace: bootstrap response received, name =");
    ndn_name_print(&name);
    putchar('\n');

    /* verify the signature */
    r = ndn_data_verify_signature(data, anchor_key_pub, sizeof(anchor_key_pub));
    if (r != 0) {
        DPRINT("producer-ace: fail to verify ace response\n");
    }
    else{
            DPRINT("producer-ace: ace response valid\n");

            ndn_block_t content;
            r = ndn_data_get_content(data, &content);
            assert(r == 0);

            /* extract content is shared secret */

            int len;
            const uint8_t* buf = content.buf;  //receive the pointer from the content type
            len = content.len; //receive the content length

            //skip content type
            buf += 1;
            len -= 1;

            //skip content length (perhaps > 255 bytes)
            uint32_t num;
            int cl = ndn_block_get_var_number(buf, len, &num); 
            buf += cl;
            len -= cl;

            //store the ask from controller-ace */
            const struct uECC_Curve_t * curve;
            #if uECC_SUPPORTS_secp160r1
                curve = uECC_secp160r1();
            #endif

            uint8_t* ace_controller = (uint8_t*)malloc(64);
            const uint8_t* ptr = buf;
            memcpy(ace_controller, ptr, 64);
            uECC_shared_secret(ace_controller, ace_key_pri, acehmac_pro, curve);
            DPRINT("producer-ace: control application processed\n");
            free(ace_controller);
            to_helper.content.ptr = &acehmac_pro;
            msg_reply(&from_helper, &to_helper);
            return NDN_APP_STOP;  
 
    }

    to_helper.content.ptr = NULL;
    return NDN_APP_STOP;  
}

static int on_timeout(ndn_block_t* interest)
{
    ndn_block_t name;
    int r = ndn_interest_get_name(interest, &name);
    assert(r == 0);

    DPRINT("ndn-helper-access (pid=%" PRIkernel_pid "): interest timeout, name =",
           handle->id);
    ndn_name_print(&name);
    putchar('\n');

    to_helper.content.ptr = NULL;
    msg_reply(&from_helper, &to_helper);
    return NDN_APP_STOP;  // block forever...
}

static int send_ace_producer_interest(void)
{
    const char* uri = "/accesscontrol";

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));

    /* append constant parameters */
    sn = ndn_name_append_from_name(&home_prefix, &sn->block);
    sn = ndn_name_append_from_name(&sn->block, &identity);

    /* parameter convention 
        1 - controller
        2 - producer
        3 - consumer
    */

    /* append ASKpub */
    sn = ndn_name_append_uint8(&sn->block, ACE_PRODUCER);
    sn = ndn_name_append_uint8(&sn->block, ACE_PRODUCER_GLOBAL);

    /* optional parameter */
    sn = ndn_name_append_uint8(&sn->block, ACE_PRODUCER_GLOBAL);

    sn = ndn_name_append(&sn->block, ace_key_pub, sizeof(ace_key_pub));

    uint32_t lifetime = 3000;  // 1 sec

    DPRINT("producer-ace (pid=%" PRIkernel_pid "): express interest, name =",
           handle->id);
    ndn_name_print(&sn->block);
    putchar('\n');

    int r = ndn_app_express_signed_interest(handle, &sn->block, NULL, lifetime,
                                            NDN_SIG_TYPE_ECDSA_SHA256, com_key_pri, 
                                            sizeof(com_key_pri), on_producer_ace, 
                                            on_timeout);                             
    ndn_shared_block_release(sn);
    if (r != 0) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int on_consumer_ace(ndn_block_t* interest, ndn_block_t* data)
{

    (void)interest;

    ndn_block_t name;
    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);

    DPRINT("consumer-ace: access application response received, name =");
    ndn_name_print(&name);
    putchar('\n');

    /* verify the signature */
    r = ndn_data_verify_signature(data, anchor_key_pub, sizeof(anchor_key_pub));
    if (r != 0) {
        DPRINT("consumer-ace: fail to verify ace response\n");
    }
    else{
            DPRINT("consumer-ace: ace response valid\n");

            ndn_block_t content;
            r = ndn_data_get_content(data, &content);
            assert(r == 0);

            /* extract content is shared secret */

            int len;
            const uint8_t* buf = content.buf;  //receive the pointer from the content type
            len = content.len; //receive the content length

            //skip content type
            buf += 1;
            len -= 1;

            //skip content length (perhaps > 255 bytes)
            uint32_t num;
            int cl = ndn_block_get_var_number(buf, len, &num); 
            buf += cl;
            len -= cl;

            //store the ask from controller-ace */
            const struct uECC_Curve_t * curve;
            #if uECC_SUPPORTS_secp160r1
                curve = uECC_secp160r1();
            #endif

            uint8_t* ace_controller = (uint8_t*)malloc(64);
            const uint8_t* ptr = buf;
            memcpy(ace_controller, ptr, 64);
            putchar('\n');
            uECC_shared_secret(ace_controller, ace_key_pri, acehmac_con, curve);
            free(ace_controller);
            ptr = NULL;
            buf += 64;
            len -= 64;

            //get the encypted seed
            uint8_t* encrypted = (uint8_t*)malloc(32);
            uint8_t* decrypted_first = (uint8_t*)malloc(32);
            uint8_t* decrypted_second = (uint8_t*)malloc(32);
            memcpy(encrypted, buf, 32);
            
            cipher_t cipher;
            uint8_t* key_1 = (uint8_t*)malloc(16);
            uint8_t* key_2 = (uint8_t*)malloc(16);

            for(int i = 0; i < 16; ++i) key_1[i] = 0;
            for(int j = 0; j < 16; ++j) key_1[j] = 0;                        

            memcpy(key_1, acehmac_con, 16);
            memcpy(key_2, acehmac_con + 16, 16);

            cipher_init(&cipher, CIPHER_AES_128, key_2, 16);
            cipher_decrypt_cbc(&cipher, TEST_1_IV, encrypted, 32, decrypted_first);

            cipher_init(&cipher, CIPHER_AES_128, key_1, 16);
            cipher_decrypt_cbc(&cipher, TEST_1_IV, decrypted_first,
                                                    32, decrypted_second);


            memcpy(producer_key, decrypted_second, 32);            

            DPRINT("consumer-ace: application response processsed\n");
            
            to_helper.content.ptr = &producer_key;
            msg_reply(&from_helper, &to_helper);

            free(encrypted);
            free(decrypted_first);
            free(decrypted_second);
            free(key_1);
            free(key_2);

            return NDN_APP_STOP;  
 
    }
    
    to_helper.content.ptr = NULL;
    return NDN_APP_STOP;
}

static int send_ace_consumer_interest(ndn_block_t* option)
{
    const char* uri = "/accesscontrol";

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));

    /* append constant parameters */
    sn = ndn_name_append_from_name(&home_prefix, &sn->block);
    sn = ndn_name_append_from_name(&sn->block, &identity);

    /* parameter convention 
        1 - controller
        2 - producer
        3 - consumer
    */

    /* append ASKpub */
    sn = ndn_name_append_uint8(&sn->block, ACE_CONSUMER);
    sn = ndn_name_append_uint8(&sn->block, ACE_CONSUMER_GLOBAL);

    sn = ndn_name_append_from_name(&sn->block, option);

    sn = ndn_name_append(&sn->block, ace_key_pub, sizeof(ace_key_pub));

    uint32_t lifetime = 3000; // 3 second
    int r = ndn_app_express_signed_interest(handle, &sn->block, NULL, lifetime,
                                            NDN_SIG_TYPE_ECDSA_SHA256, com_key_pri, 
                                            sizeof(com_key_pri), on_consumer_ace, 
                                            on_timeout);        

    ndn_shared_block_release(sn);
    if (r != 0) {
        DPRINT("consumer-ace (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }
    return NDN_APP_CONTINUE;
}

void *ndn_helper_access(void* bootstrapTuple)
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
    ndn_shared_block_t* identity_name = ndn_name_move_from_comp(&host);   
    DPRINT("ndn-helper-access (pid=%" PRIkernel_pid "): identity name: ",
               thread_getpid());
    ndn_name_print(&identity_name->block); 
    putchar('\n');

    identity = identity_name->block;

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("ndn-helper-access  (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return NULL;
    }

    /* discovery event loop */
    msg_t msg_q[_MSG_QUEUE_SIZE];
    msg_init_queue(msg_q, _MSG_QUEUE_SIZE);

    int shouldStop = false;

    /* start event loop */
    while (!shouldStop) {
        msg_receive(&from_helper);

        switch (from_helper.type) {
            case NDN_HELPER_ACCESS_PRODUCER:
                DPRINT("ndn-helper-access (pid=%" PRIkernel_pid "): producer access control\n",
                        thread_getpid());

                /* initiate ace key pair */
                ndn_access_t* ptr_pro = from_helper.content.ptr;
                memcpy(ace_key_pub, ptr_pro->ace->pub, 64);
                memcpy(ace_key_pri, ptr_pro->ace->pvt, 32);

                send_ace_producer_interest();
                ndn_app_run(handle); //success if back here
                //shouldStop = true;

                break;

            case NDN_HELPER_ACCESS_CONSUMER:
                DPRINT("ndn-helper-access (pid=%" PRIkernel_pid "): consumer access control\n",
                        thread_getpid());
                
                ndn_access_t* ptr_con = from_helper.content.ptr;
                memcpy(ace_key_pub, ptr_con->ace->pub, 64);
                memcpy(ace_key_pri, ptr_con->ace->pvt, 32);

                ndn_block_t* option = ptr_con->opt;

                send_ace_consumer_interest(option);
                ndn_app_run(handle);
                //shouldStop = true;
                break;

            case NDN_HELPER_ACCESS_TERMINATE:
                DPRINT("ndn-helper-access (pid=%" PRIkernel_pid "): access control terminate\n",
                        thread_getpid());
                shouldStop = true;
                break;

            default:
                break;
        }

    }
    ndn_app_destroy(handle);
    return NULL;
}
