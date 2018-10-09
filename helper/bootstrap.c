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
#include "../encoding/data.h"
#include "../msg-type.h"
#include "crypto/ciphers.h"
#include "uECC.h"
#include <string.h>
#include "bootstrap.h"
#include "../security.h"
#include "helper-block.h"
#include "helper-constants.h"

#define DPRINT(...) printf(__VA_ARGS__)

//ecc key generated for communication use (CK)

static uint8_t anchor_key_pub[64] = {0};
static ndn_block_t token;

static ndn_app_t* handle = NULL;

static ndn_block_t anchor_global;
static ndn_block_t certificate_global;
static ndn_block_t home_prefix;

static uint64_t dh_p = 10000831;
static uint64_t dh_g = 10000769;
static uint32_t secrete_1[4];
static uint64_t bit_1[4];
static uint64_t bit_2[4];
static uint64_t shared[4];

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


static uint8_t ecc_key_pri[32];
static uint8_t ecc_key_pub[64]; // this is secp160r1 key

static msg_t to_helper, from_helper;
static ndn_bootstrap_t bootstrapTuple;

static uint64_t Montgomery(uint64_t n, uint32_t p, uint64_t m)     
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
    ndn_block_t name1;
    (void)interest;

    int r = ndn_data_get_name(data, &name1);  //need implementation
    assert(r == 0);
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") Certificate Response received, name =",
            handle->id );
    ndn_name_print(&name1);
    putchar('\n');

    r = ndn_data_verify_signature(data, (uint8_t*)shared, 8 * 4); 
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
  // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}


    /* append the "cert" */
    const char* uri = "/cert";  //info from the manufacturer
    ndn_shared_block_t* sn_cert = ndn_name_from_uri(uri, strlen(uri));
    ndn_shared_block_t* sn = ndn_name_append_from_name(&home_prefix, &sn_cert->block);
    ndn_shared_block_release(sn_cert);
    
    /* append the digest of BKpub */
    uint8_t* buf_di = (uint8_t*)malloc(32);  //32 bytes reserved for hash
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_di);                       
    sn = ndn_name_append(&sn->block, buf_di, 32);   
    free(buf_di);
    buf_di = NULL;

    /* apppend the CKpub */  
    sn = ndn_name_append(&sn->block, com_key_pub, sizeof(com_key_pub)); 
 
    /* make the signature of token */
    /* make a block for token */
    uint8_t* buf_tk = (uint8_t*)malloc(34); //32 bytes reserved from the value, 2 bytes for header
    ndn_security_make_hmac_signature((uint8_t*)shared, &token, buf_tk);

    /* append the signature of token */
    sn = ndn_name_append(&sn->block, buf_tk, 34);
    free((void*)buf_tk);
    buf_tk = NULL;

    //append the timestamp
    sn = ndn_name_append_uint32(&sn->block, xtimer_now_usec());

    //append the random value
    sn = ndn_name_append_uint32(&sn_cert->block, random_uint32());

    uint32_t lifetime = 3000; 
    int r = ndn_app_express_signed_interest(handle, &sn->block, NULL, 
                                            lifetime, NDN_SIG_TYPE_HMAC_SHA256,
                                            (uint8_t*)shared, 32,
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
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") content L length= %d\n", handle->id, cl);
    buf += cl;
    len -= cl;

    //skip token's TLV (and push it back completely)
    token.buf = buf;
    token.len = 34;
    buf += 2;
    len -= 2;//skip header
    //process the token (4 * uint64_t)
    memcpy(bit_2, buf, 32); buf += 32; len -= 32;

    /*
    Diffie Hellman
        Alice and Bob agree to use a modulus p = 23 and base g = 5 (which is a primitive root modulo 23).
        Alice chooses a secret integer a = 4, then sends Bob A = g^a mod p
        A = 5^4 mod 23 = 4
        Bob chooses a secret integer b = 3, then sends Alice B = g^b mod p
        B = 5^3 mod 23 = 10
        Alice computes s = B^a mod p
        s = 10^4 mod 23 = 18
        Bob computes s = A^b mod p
        s = 4^3 mod 23 = 18
    */

    shared[0] = Montgomery(bit_2[0], secrete_1[0], dh_p);
    shared[1] = Montgomery(bit_2[1], secrete_1[1], dh_p);
    shared[2] = Montgomery(bit_2[2], secrete_1[2], dh_p);
    shared[3] = Montgomery(bit_2[3], secrete_1[3], dh_p);

    //skip 32 bytes of public key's hash (plus 2 types header)
    buf += 34;
    len -= 34;

    //set the anchor certificate
    anchor_global.buf = buf;
    anchor_global.len = len;
   
    //get certificate name - home prefix
    ndn_data_get_name(&anchor_global, &home_prefix);
    DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") anchor certificate name =", handle->id);
    ndn_name_print(&home_prefix);
    putchar('\n');

    //then we need verify anchor's signature
    ndn_block_t AKpub;
    ndn_data_get_content(&anchor_global, &AKpub);

    memcpy(&anchor_key_pub, AKpub.buf + 2, 64);//skip the content and pubkey TLV header

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
     // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}

     
    const char* uri = "/ndn/sign-on";   
    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
        DPRINT("ndn-helper-bootstrap: (pid=%" PRIkernel_pid ") cannot create name from uri ", handle->id);
        return NDN_APP_ERROR;
    }   //we creat a name first

    //making and append the digest of BKpub      //don't have header
    uint8_t* buf_dibs = (uint8_t*)malloc(32);  
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_dibs);                       
    sn = ndn_name_append(&sn->block, buf_dibs, 32);   
    free(buf_dibs);

    //TODO: 256bit Diffie Hellman 
    secrete_1[0]  = random_uint32();
    secrete_1[1]  = random_uint32();
    secrete_1[2]  = random_uint32();
    secrete_1[3]  = random_uint32();

    /*
        Alice and Bob agree to use a modulus p = 23 and base g = 5 (which is a primitive root modulo 23).
        Alice chooses a secret integer a = 4, then sends Bob A = g^a mod p
        A = 5^4 mod 23 = 4
        Bob chooses a secret integer b = 3, then sends Alice B = g^b mod p
        B = 5^3 mod 23 = 10
        Alice computes s = B^a mod p
        s = 10^4 mod 23 = 18
        Bob computes s = A^b mod p
        s = 4^3 mod 23 = 18
    */

    bit_1[0] = Montgomery(dh_g, secrete_1[0], dh_p);
    bit_1[1] = Montgomery(dh_g, secrete_1[1], dh_p);
    bit_1[2] = Montgomery(dh_g, secrete_1[2], dh_p);
    bit_1[3] = Montgomery(dh_g, secrete_1[3], dh_p);
    
    //append the bit_1
    uint8_t* buf_dh = (uint8_t*)malloc(8 * 4);
    memcpy(buf_dh, bit_1, 32);
    sn = ndn_name_append(&sn->block, buf_dh, 32);

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
    
    memcpy(ecc_key_pub, key->pub, 64);
    memcpy(ecc_key_pri, key->pvt, 32);
    
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