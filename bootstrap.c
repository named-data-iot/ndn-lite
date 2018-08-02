#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include "app.h"
#include "ndn.h"
#include "encoding/name.h"
#include "encoding/interest.h"
#include "nfl-constant.h"
#include "encoding/data.h"
#include "msg-type.h"
#include "crypto/ciphers.h"
#include "uECC.h"
#include <string.h>
#include "nfl-block.h"
#include "bootstrap.h"

#ifndef FEATURE_PERIPH_HWRNG
typedef struct uECC_SHA256_HashContext {
    uECC_HashContext uECC;
    sha256_context_t ctx;
} uECC_SHA256_HashContext;
static void _init_sha256(const uECC_HashContext *base)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_init(&context->ctx);
}

static void _update_sha256(const uECC_HashContext *base,
                           const uint8_t *message,
                           unsigned message_size)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_update(&context->ctx, message, message_size);
}

static void _finish_sha256(const uECC_HashContext *base, uint8_t *hash_result)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_final(&context->ctx, hash_result);
}
#endif


#define DPRINT(...) printf(__VA_ARGS__)

//ecc key generated for communication use (CK)

static uint8_t anchor_key_pub[64] = {0};
static ndn_block_t token;

static ndn_app_t* handle = NULL;
static uint32_t begin;

static ndn_block_t anchor_global;
static ndn_block_t certificate_global;
static ndn_block_t home_prefix;
static ndn_block_t com_cert;
static nfl_bootstrap_tuple_t tuple;

static uint8_t ecc_key_pri[] = {             
     0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
     0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
     0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
     0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
 };

static uint8_t ecc_key_pub[] = {
    0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
    0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
    0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
    0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
    0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
    0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};

static uint8_t com_key_pri[] = {             
     0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
     0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
     0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
     0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
 };

static uint8_t com_key_pub[] = {
    0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
    0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
    0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
    0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
    0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
    0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};

//segment for signature and buffer_signature to write, returning the pointer to the buffer
//this function will automatically skip the NAME header, so just pass the whole NAME TLV 
static int ndn_make_signature(uint8_t pri_key[32], ndn_block_t* seg, uint8_t* buf_sig)
{
    uint32_t num;
    buf_sig[0] = NDN_TLV_SIGNATURE_VALUE;
    ndn_block_put_var_number(64, buf_sig + 1, 66 -1);
    int gl = ndn_block_get_var_number(seg->buf + 1, seg->len - 1, &num);
    uint8_t h[32] = {0}; 

    sha256(seg->buf + 1 + gl, seg->len - 1 - gl, h);
    uECC_Curve curve = uECC_secp256r1();

#ifndef FEATURE_PERIPH_HWRNG
    // allocate memory on heap to avoid stack overflow
    uint8_t *tmp = (uint8_t*)malloc(32 + 32 + 64);
    if (tmp == NULL) {
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }

    uECC_SHA256_HashContext *ctx = (uECC_SHA256_HashContext*)
                malloc(sizeof(uECC_SHA256_HashContext));
    if (ctx == NULL) {
        free(tmp);
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }
       
    ctx->uECC.init_hash = &_init_sha256;
    ctx->uECC.update_hash = &_update_sha256;
    ctx->uECC.finish_hash = &_finish_sha256;
    ctx->uECC.block_size = 64;
    ctx->uECC.result_size = 32;
    ctx->uECC.tmp = tmp;
    int res = uECC_sign_deterministic(pri_key, h, sizeof(h), &ctx->uECC,
                                              buf_sig + 1 + gl, curve); 
    free(ctx);
    free(tmp);
    if (res == 0) {
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }
#else
    res = uECC_sign(pri_key, h, sizeof(h), buf_sig + 1 + gl, curve);
    if (res == 0) {
        return -1;
    }  
    return 0; //success
#endif
    return 0; //success
}

static int bootstrap_timeout(ndn_block_t* interest);

static int certificate_timeout(ndn_block_t* interest);

static int on_certificate_response(ndn_block_t* interest, ndn_block_t* data)
{
    /*
    Incoming Packet Format
    Name: I2/version
    Content: BKpuk
    Signature: sign by AKpri
    */

    ndn_block_t name1;
    (void)interest;

    int r = ndn_data_get_name(data, &name1);  //need implementation
    assert(r == 0);
    DPRINT("certificate response received, name=");
    ndn_name_print(&name1);
    putchar('\n');

    r = ndn_data_verify_signature(data, anchor_key_pub, sizeof(anchor_key_pub)); 
    if (r != 0)
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): fail to verify certificate response\n",
               handle->id);
    else{ 
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): certificate response valid\n",
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
   
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): certificate installed, length = %d\n",
               handle->id, certificate_global.len);
    }
    return NDN_APP_STOP;  // block forever...
}

static int ndn_app_express_certificate_request(void) 
{
  // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}


    /* append the "cert" */
    const char* uri_cert = "/cert";  //info from the manufacturer
    ndn_shared_block_t* sn_cert = ndn_name_from_uri(uri_cert, strlen(uri_cert));
    //move the pointer by 4 bytes: 2 bytes for name header, 2 bytes for component header
    ndn_shared_block_t* sn1_cert = ndn_name_append(&home_prefix,
                                 (&sn_cert->block)->buf + 4, (&sn_cert->block)->len - 4);

    ndn_shared_block_release(sn_cert);
    
    /* append the digest of BKpub */
    uint8_t* buf_di = (uint8_t*)malloc(32);  //32 bytes reserved for hash
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_di);                       
    ndn_shared_block_t* sn2_cert = ndn_name_append(&sn1_cert->block, buf_di, 32);   
    free((void*)buf_di);
    buf_di = NULL;
    ndn_shared_block_release(sn1_cert);

    /* apppend the device name */  
    const char* uri1_cert = "/device_1";  //info from device itself
    ndn_shared_block_t* sn3_cert = ndn_name_from_uri(uri1_cert, strlen(uri1_cert));
    //move the pointer by 4 bytes: 2 bytes for name header, 2 bytes for component header
    ndn_shared_block_t* sn4_cert = ndn_name_append(&home_prefix,
                                   (&sn3_cert->block)->buf + 4, (&sn3_cert->block)->len - 4);
    ndn_shared_block_release(sn3_cert);

    ndn_block_t keybuffer = {com_key_pub, sizeof(com_key_pub)};
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };
    ndn_shared_block_t* signed_com =
        ndn_data_create(&sn4_cert->block, &meta, &keybuffer,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        com_key_pri, sizeof(com_key_pri));
    if (signed_com == NULL) {
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): cannot create self signed Communnication Certificate\n",
               handle->id);
        ndn_shared_block_release(sn4_cert);
        return NDN_APP_ERROR;
    }

    com_cert = signed_com->block;

    ndn_shared_block_t* sn5_cert = ndn_name_append(&sn2_cert->block, signed_com->block.buf, signed_com->block.len); 
    ndn_shared_block_release(sn2_cert);
 
    /* make the signature of token */
    /* make a block for token */
    uint8_t* buf_tk = (uint8_t*)malloc(66); //64 bytes reserved from the value, 2 bytes for header
    ndn_make_signature(com_key_pri, &token, buf_tk);

    /* append the signature of token */
    ndn_shared_block_t* sn6_cert = ndn_name_append(&sn5_cert->block, buf_tk, 66);
    free((void*)buf_tk);
    buf_tk = NULL;
    ndn_shared_block_release(sn5_cert);

    //append the timestamp
    ndn_shared_block_t* sn7_cert = ndn_name_append_uint32(&sn6_cert->block, xtimer_now_usec());
    ndn_shared_block_release(sn6_cert);

    //append the random value
    ndn_shared_block_t* sn8_cert = ndn_name_append_uint32(&sn7_cert->block, random_uint32());
    ndn_shared_block_release(sn7_cert); 

    //now we have signinfo but carrying no keylocator
    // Write signature info header 
    uint8_t* buf_sinfo1 = (uint8_t*)malloc(5); 
    buf_sinfo1[0] = NDN_TLV_SIGNATURE_INFO;
    buf_sinfo1[1] = 3;

    // Write signature type (true signatureinfo content)
    buf_sinfo1[2] = NDN_TLV_SIGNATURE_TYPE;
    buf_sinfo1[3] = 1;
    buf_sinfo1[4] = NDN_SIG_TYPE_ECDSA_SHA256;

    //append the signatureinfo
    ndn_shared_block_t* sn9_cert = ndn_name_append(&sn8_cert->block, buf_sinfo1, 5); 
    free((void*)buf_sinfo1);
    buf_sinfo1 = NULL;
    ndn_shared_block_release(sn8_cert);

    /* append the signature by BKpub */
    uint8_t* buf_bk = (uint8_t*)malloc(66); //64 bytes reserved from the value, 2 bytes for header 
    ndn_make_signature(ecc_key_pri, &sn9_cert->block, buf_bk);
    ndn_shared_block_t* sn10_cert = ndn_name_append(&sn9_cert->block, buf_bk, 66);   
    free((void*)buf_bk);
    buf_bk = NULL;
    ndn_shared_block_release(sn9_cert);

    DPRINT("nfl-bootstrap: express Certificate Request, name=");
    ndn_name_print(&sn10_cert->block);
    putchar('\n');

    begin = xtimer_now_usec();
    uint32_t lifetime = 3000;  // 1 sec
    int r = ndn_app_express_interest(handle, &sn10_cert->block, NULL, lifetime,
                                     on_certificate_response, 
                                     certificate_timeout); 
    ndn_shared_block_release(sn10_cert);
    ndn_shared_block_release(sn4_cert);
    if (r != 0) {
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int on_bootstrapping_response(ndn_block_t* interest, ndn_block_t* data)
{
    /* 
    Incoming Packet Format
    Name: echo of I1->append /version
    Content: token
             BKpub digest
             anchor certificate
                               Name:  anchor prefix
                               Content： AKpub
                               Signature: AKpri
    Signature: AKpri
    */
    (void)interest;
    ndn_block_t name;
    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);
    DPRINT("nfl-bootstrap: bootstrap response received, name=");
    ndn_name_print(&name);
    putchar('\n');

    ndn_block_t content;
    r = ndn_data_get_content(data, &content);
    assert(r == 0);

    uint32_t len; 
    //l = ndn_block_get_var_number(data->buf + 1, data->len - 1, &len);
    //DPRINT("Data L: %u\n", len);

    //ndn_block_get_var_number(data->buf + 1 + l + 1, data->len - 1 - l - 1, &len);
    //DPRINT("Name L: %u\n", len);
    //DPRINT("Name block length from function: %d\n", name.len);


    const uint8_t* buf = content.buf;  //receive the pointer from the content type
    len = content.len; //receive the content length
    //DPRINT("content TLV length: %u\n", len);
    //skip content type
    buf += 1;
    len -= 1;

    //skip content length (perhaps > 255 bytes)
    uint32_t num;
    int cl = ndn_block_get_var_number(buf, len, &num); 
    DPRINT("nfl-bootstrap: content L length= %d\n", cl);
    buf += cl;
    len -= cl;

    //skip token's TLV (and push it back completely)
    token.buf = buf;
    token.len = 10;
    buf += 10;
    len -= 10;

    //skip 32 bytes of public key's hash (plus 2 types header)
    buf += 34;
    len -= 34;

    //set the anchor certificate
    anchor_global.buf = buf;
    anchor_global.len = len;
   
    DPRINT("nfl-bootstrap: anchor certificate length: %d\n", anchor_global.len);
    //get certificate name - home prefix
    ndn_data_get_name(&anchor_global, &home_prefix);
    DPRINT("nfl-bootstrap: anchor certificate name=");
    ndn_name_print(&home_prefix);
    putchar('\n');

    //then we need verify anchor's signature
    ndn_block_t AKpub;
    ndn_data_get_content(&anchor_global, &AKpub);
    DPRINT("nfl-bootstrap: anchor public key TLV block length: %d\n", AKpub.len);
    memcpy(&anchor_key_pub, AKpub.buf + 2, 64);//skip the content and pubkey TLV header

    r = ndn_data_verify_signature(&anchor_global, anchor_key_pub, sizeof(anchor_key_pub));
    if (r != 0)
        DPRINT("nfl-bootstrap: fail to verify sign-on response\n");
    else{
        DPRINT("nfl-bootstrap: sign-on response valid\n");
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
        DPRINT("nfl-bootstrap: cannot create name from uri ");
        return NDN_APP_ERROR;
    }   //we creat a name first

    //making and append the digest of BKpub      //don't have header
    uint8_t* buf_dibs = (uint8_t*)malloc(32);  
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_dibs);                       
    ndn_shared_block_t* sn1 = ndn_name_append(&sn->block, buf_dibs, 32);   
    free(buf_dibs);
    ndn_shared_block_release(sn);

    //now we have signinfo but carrying no keylocator
    // Write signature info header 
    uint8_t* buf_sinfo = (uint8_t*)malloc(5); 
    buf_sinfo[0] = NDN_TLV_SIGNATURE_INFO;
    ndn_block_put_var_number(3, buf_sinfo + 1, 5 - 1);

    // Write signature type (true signatureinfo content)
    buf_sinfo[2] = NDN_TLV_SIGNATURE_TYPE;
    ndn_block_put_var_number(1, buf_sinfo + 3, 5 - 3);
    buf_sinfo[4] = NDN_SIG_TYPE_ECDSA_SHA256;

    //append the signatureinfo
    ndn_shared_block_t* sn2 = ndn_name_append(&sn1->block, buf_sinfo, 5); 
    free(buf_sinfo);
    ndn_shared_block_release(sn1);

    //making and append ECDSA signature by BKpri
    uint8_t* buf_sibs = (uint8_t*)malloc(66); //64 bytes for the value, 2 bytes for header 
    ndn_make_signature(ecc_key_pri, &sn2->block, buf_sibs);
    ndn_shared_block_t* sn3 = ndn_name_append(&sn2->block, buf_sibs, 66);  //from what part we sign?
    ndn_shared_block_release(sn2);
    free(buf_sibs);


    DPRINT("nfl-bootstrap: express bootstrap interest, name=");
    ndn_name_print(&sn3->block);
    putchar('\n');

    begin = xtimer_now_usec();
    uint32_t lifetime = 3000;  // 1 sec
    int r = ndn_app_express_interest(handle, &sn3->block, NULL, lifetime,
                                     on_bootstrapping_response, 
                                     bootstrap_timeout);  
    ndn_shared_block_release(sn3);
    if (r != 0) {
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int bootstrap_timeout(ndn_block_t* interest)
{
    (void)interest;
    DPRINT("Bootstrapping Request Timeout\n");
    //ndn_app_express_bootstrapping_request();
    return NDN_APP_CONTINUE; 
}
static int certificate_timeout(ndn_block_t* interest)
{
    (void)interest;
    DPRINT("Certificate Request Timeout\n");
    //ndn_app_express_certificate_request();
    return NDN_APP_CONTINUE; 
}

void *ndn_bootstrap(void *ptr)
{
    (void)ptr;

    msg_t msg, reply;
    

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return NULL;
    }

    ndn_app_express_bootstrapping_request();  /* where all bootstrapping start */

    DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): enter app run loop\n",
           handle->id);

    ndn_app_run(handle);

    DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): returned from app run loop\n",
           handle->id);

    DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): into ipc loop\n", handle->id);

    while(1){
    msg_receive(&msg);
    DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): ipc request got\n", handle->id);
    tuple.m_cert = &certificate_global;
    tuple.anchor_cert = &anchor_global;
    tuple.home_prefix = &home_prefix;
    reply.content.ptr = &tuple;
    msg_reply(&msg, &reply);
    DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): ipc loop quit\n", handle->id);
    break; 
    }

    ndn_app_destroy(handle);
    return NULL;
}