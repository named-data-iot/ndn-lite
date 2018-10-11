#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include "crypto/ciphers.h"
#include "uECC.h"
#include "../app.h"
#include "../ndn.h"
#include "../encoding/name.h"
#include "../encoding/interest.h"
#include "../encoding/data.h"
#include "../msg-type.h"
#include "../security.h"
#include "helper-block.h"
#include "helper-msg.h"
#include "bootstrap.h"

#define DPRINT(...) printf(__VA_ARGS__)

//ecc key generated for communication use (CK)

static uint8_t anchor_key_pub[NDN_CRYPTO_ASYMM_PUB] = {0};
static ndn_block_t token_receive;

static ndn_app_t* handle = NULL;

static ndn_block_t anchor_global;
static ndn_block_t certificate_global;
static ndn_block_t home_prefix;

static uint64_t dh_p = 10000831; //shared_tsk via out-of-band approach
static uint64_t dh_g = 10000769;
static uint32_t secrete[4];
static uint64_t dh_send[4];
static uint64_t dh_receive[4];
static uint64_t shared_tsk[4];

/*static uint8_t com_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};*/

static uint8_t com_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key


static uint8_t ecc_key_pri[NDN_CRYPTO_ASYMM_PVT];
static uint8_t ecc_key_pub[NDN_CRYPTO_ASYMM_PUB]; // this is secp160r1 key

static msg_t to_helper, from_helper; 
static ndn_bootstrap_t bootstrapTuple;

/* montgomery algorithm used to do power & mode operation */
static uint64_t montgomery(uint64_t n, uint32_t p, uint64_t m)     
{      
    uint64_t r = n % m;     
    uint64_t tmp = 1;     
    while (p > 1)     
    {     
        if ((p & 1)!=0)     
        {     
            tmp = (tmp * r) % m;     
        }     
        r = (r * r) % m;     
        p >>= 1;     
    }     
    return (r * tmp) % m;     
}    

static int bootstrap_timeout(ndn_block_t* interest);

static int certificate_timeout(ndn_block_t* interest);

static int on_certificate_response(ndn_block_t* interest, ndn_block_t* data)
{
    ndn_block_t name;
    (void)interest;

    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") Certificate Response received, name =",
            handle->id );
    ndn_name_print(&name);
    putchar('\n');

    r = ndn_data_verify_signature(data, (uint8_t*)shared_tsk, NDN_CRYPTO_SYMM_KEY); 
    if (r != 0)
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid "): fail to verify certificate response, use HMAC\n",
               handle->id);
    else{ 
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid "): certificate response valid, use HMAC\n",
               handle->id);

        /* install the certificate */
        ndn_block_t content_cert;
        r = ndn_data_get_content(data, &content_cert);
        assert(r == 0);
        
        const uint8_t* buf_cert = content_cert.buf;
        
        //skip the content header and install the global certificate
        buf_cert += 2;
        certificate_global.buf = buf_cert;
        certificate_global.len = content_cert.len - 2;
   
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid "): certificate installed, length = %d\n",
               handle->id, certificate_global.len);
    }

    bootstrapTuple.certificate = certificate_global;
    bootstrapTuple.anchor = anchor_global;
    bootstrapTuple.home_prefix = home_prefix;

    to_helper.content.ptr = &bootstrapTuple;
    msg_reply(&from_helper, &to_helper);

    return NDN_APP_STOP;  // block forever...
}

static int ndn_app_express_certificate_request(void) 
{
   /* Outgoing Interest-2: /{home prefix}/cert/{digest of BKpub}/{CKpub}
    *                      /{signature of Token}/{HMAC signature}
    */

    /* append the "cert" */
    const char* uri = "/cert";  //info from the manufacturer
    ndn_shared_block_t* sn_cert = ndn_name_from_uri(uri, strlen(uri));
    ndn_shared_block_t* sn = ndn_name_append_from_name(&home_prefix, &sn_cert->block);
    ndn_shared_block_release(sn_cert);
    
    /* append the digest of BKpub */
    uint8_t* hash = (uint8_t*)malloc(NDN_CRYPTO_HASH); 
    sha256(ecc_key_pub, sizeof(ecc_key_pub), hash);                       
    sn = ndn_name_append(&sn->block, hash, NDN_CRYPTO_HASH);   
    free(hash);
    hash = NULL;

    /* apppend the CKpub */  
    sn = ndn_name_append(&sn->block, com_key_pub, sizeof(com_key_pub)); 
 
    /* make the signature of token_receive */
    //32 bytes reserved from the value, 2 bytes for header
    uint8_t* signed_token = (uint8_t*)malloc(NDN_CRYPTO_TOKEN + 2);
    
    ndn_security_make_hmac_signature((uint8_t*)shared_tsk, &token_receive, signed_token);

    /* append the signature of token_receive */
    sn = ndn_name_append(&sn->block, signed_token, NDN_CRYPTO_TOKEN + 2);
    free((void*)signed_token);
    signed_token = NULL;

    uint32_t lifetime = 3000;  // 3 seconds
    int r = ndn_app_express_signed_interest(handle, &sn->block, NULL, 
                                            lifetime, NDN_SIG_TYPE_HMAC_SHA256,
                                            (uint8_t*)shared_tsk, NDN_CRYPTO_SYMM_KEY,
                                            on_certificate_response, 
                                            certificate_timeout); 
    ndn_shared_block_release(sn);
    if (r != 0) {
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int on_bootstrapping_response(ndn_block_t* interest, ndn_block_t* data)
{
    (void)interest;
    ndn_block_t name;
    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") bootstrap response received, name =", handle->id);
    ndn_name_print(&name);
    putchar('\n');

    ndn_block_t content;
    r = ndn_data_get_content(data, &content);
    assert(r == 0);

    uint32_t len; 
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

    //skip token_receive's header and process the token_receive bits
    token_receive.buf = buf;
    token_receive.len = NDN_CRYPTO_TOKEN + 2;
    buf += 2;
    len -= 2;    
    memcpy(dh_receive, buf, NDN_CRYPTO_TOKEN); 
    buf += NDN_CRYPTO_TOKEN; 
    len -= NDN_CRYPTO_TOKEN;

    shared_tsk[0] = montgomery(dh_receive[0], secrete[0], dh_p);
    shared_tsk[1] = montgomery(dh_receive[1], secrete[1], dh_p);
    shared_tsk[2] = montgomery(dh_receive[2], secrete[2], dh_p);
    shared_tsk[3] = montgomery(dh_receive[3], secrete[3], dh_p);

    //TODO: to verify the BKpub here
    buf += NDN_CRYPTO_HASH + 2;
    len -= NDN_CRYPTO_HASH + 2;

    //set the anchor certificate
    anchor_global.buf = buf;
    anchor_global.len = len;
   
    //get certificate name - home prefix
    ndn_data_get_name(&anchor_global, &home_prefix);
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") anchor certificate name =", handle->id);
    ndn_name_print(&home_prefix);
    putchar('\n');

    //then we need verify anchor's signature
    ndn_block_t anchor_pub;
    ndn_data_get_content(&anchor_global, &anchor_pub);

    //skip content header
    memcpy(&anchor_key_pub, anchor_pub.buf + 2, NDN_CRYPTO_ASYMM_PUB); 

    r = ndn_data_verify_signature(&anchor_global, anchor_key_pub, sizeof(anchor_key_pub));
    if (r != 0)
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") fail to verify sign-on response\n", handle->id);
    else{
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") sign-on response valid\n", handle->id);
        ndn_app_express_certificate_request(); 
    }

    return NDN_APP_CONTINUE;  // block forever...
}

static int ndn_app_express_bootstrapping_request(void)
{
   /* Outgoing Interest-1: /ndn/sign-on/{digest of BKpub}/{Diffie Hellman Token}
    *                      /{ECDSA signature by BKpri}
    */
     
    const char* uri = "/ndn/sign-on";   
    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") cannot create name from uri ", handle->id);
        return NDN_APP_ERROR;
    }   

    //making and append the digest of BKpub     
    uint8_t* hash = (uint8_t*)malloc(NDN_CRYPTO_HASH);  
    sha256(ecc_key_pub, sizeof(ecc_key_pub), hash);                       
    sn = ndn_name_append(&sn->block, hash, NDN_CRYPTO_HASH);   
    free(hash);

    secrete[0]  = random_uint32();
    secrete[1]  = random_uint32();
    secrete[2]  = random_uint32();
    secrete[3]  = random_uint32();

    dh_send[0] = montgomery(dh_g, secrete[0], dh_p);
    dh_send[1] = montgomery(dh_g, secrete[1], dh_p);
    dh_send[2] = montgomery(dh_g, secrete[2], dh_p);
    dh_send[3] = montgomery(dh_g, secrete[3], dh_p);
    
    //append the dh_send
    uint8_t* token_send = (uint8_t*)malloc(NDN_CRYPTO_TOKEN);
    memcpy(token_send, dh_send, NDN_CRYPTO_TOKEN);
    sn = ndn_name_append(&sn->block, token_send, NDN_CRYPTO_TOKEN);

    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") express bootstrap interest, name =", handle->id);
    ndn_name_print(&sn->block);
    putchar('\n');

    uint32_t lifetime = 3000;  // 3 sec
    int r = ndn_app_express_signed_interest(handle, &sn->block, NULL, lifetime,
                                            NDN_SIG_TYPE_ECDSA_SHA256, ecc_key_pri,
                                            sizeof(ecc_key_pri),
                                            on_bootstrapping_response, 
                                            bootstrap_timeout);  
    ndn_shared_block_release(sn);
    if (r != 0) {
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int bootstrap_timeout(ndn_block_t* interest)
{
    (void)interest;
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") Bootstrapping Request Timeout\n", handle->id);
    
    to_helper.content.ptr = NULL;
    msg_reply(&from_helper, &to_helper);

    return NDN_APP_STOP; 
}
static int certificate_timeout(ndn_block_t* interest)
{
    (void)interest;
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") Certificate Request Timeout\n", handle->id);
    
    to_helper.content.ptr = NULL;
    msg_reply(&from_helper, &to_helper);

    return NDN_APP_STOP; 
}

void *ndn_helper_bootstrap(void *ptr)
{
    //make copy of key pair
    ndn_keypair_t* key = NULL;
    key = ptr;
    
    memcpy(ecc_key_pub, key->pub, NDN_CRYPTO_ASYMM_PUB);
    memcpy(ecc_key_pri, key->pvt, NDN_CRYPTO_ASYMM_PVT);
    
    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return NULL;
    }

    while(1){
        msg_receive(&from_helper);

        if (from_helper.type == NDN_HELPER_BOOTSTRAP_START) {
            DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") APP_BOOTSTRAP_START message received from pid %"
                PRIkernel_pid "\n", handle->id, from_helper.sender_pid);
            break;
        }

        else{
            DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ")  unknown type message received from pid %"
                PRIkernel_pid "\n", handle->id, from_helper.sender_pid);
            to_helper.content.ptr = NULL;
            msg_reply(&from_helper, &to_helper);

            return NULL;      
        }    
    }

    ndn_app_express_bootstrapping_request();  /* where all bootstrapping start */
    ndn_app_run(handle);
    ndn_app_destroy(handle);

    return NULL;
}