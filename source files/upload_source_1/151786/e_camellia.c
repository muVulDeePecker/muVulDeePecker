/* crypto/evp/e_camellia.c -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CAMELLIA
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/camellia.h>
#include "evp_locl.h"
#include <mongoose.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <sys/stat.h> 
static int camellia_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc);
/* Camellia subkey Structure */
typedef struct {
CAMELLIA_KEY ks;}EVP_CAMELLIA_KEY;
/* Attribute operation for Camellia */
#define data(ctx)	EVP_C_DATA(EVP_CAMELLIA_KEY,ctx)
int monosepalous_untwists = 0;
typedef char *restrainer_disjoinable;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *intercalation_galilee);
void* stonesoup_printf_context;
void stonesoup_setup_printf_context() {
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    // mg_send_header(stonesoup_printf_context, "Content-Type", "text/plain");
    va_start(argptr, format);
    mg_vprintf_data((struct mg_connection*) stonesoup_printf_context, format, argptr);
    va_end(argptr);
}
void stonesoup_close_printf_context() {
}
static int stonesoup_exit_flag = 0;
static int stonesoup_ev_handler(struct mg_connection *conn, enum mg_event ev) {
  char * ifmatch_header;
  char* stonesoup_tainted_buff;
  int buffer_size = 1000;
  int data_size = 0;
  if (ev == MG_REQUEST) {
    ifmatch_header = (char*) mg_get_header(conn, "if-match");
    if (strcmp(ifmatch_header, "weak_taint_source_value") == 0) {
        while (1) {
            stonesoup_tainted_buff = (char*) malloc(buffer_size * sizeof(char));
            /* STONESOUP: SOURCE-TAINT (Socket Variable) */
            data_size = mg_get_var(conn, "data", stonesoup_tainted_buff, buffer_size * sizeof(char));
            if (data_size < buffer_size) {
                stonesoup_exit_flag = 1;
                break;
            }
            buffer_size = buffer_size * 2;
            free(stonesoup_tainted_buff);
        }
        stonesoup_printf_context = conn;
        stonesoup_handle_taint(stonesoup_tainted_buff);
        /* STONESOUP: INJECTION-POINT */
    }
    return MG_TRUE;
  } else if (ev == MG_AUTH) {
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}
void stonesoup_read_taint(void) {
  if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
      strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
    struct mg_server *stonesoup_server = mg_create_server(NULL, stonesoup_ev_handler);
    mg_set_option(stonesoup_server, "listening_port", "8887");
    while (1) {
      if (mg_poll_server(stonesoup_server, 1000) == 0 && stonesoup_exit_flag == 1) {
          break;
      }
    }
    mg_destroy_server(&stonesoup_server);
  }
}
void vitalisation_ismarus(int fallon_synthete,restrainer_disjoinable **kermit_huntington);

static int camellia_128_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    Camellia_cbc_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    Camellia_cbc_encrypt(in,out,((long )inl),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
  }
  return 1;
}

static int camellia_128_cfb128_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (128 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb128_encrypt(in,out,((long )(128 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}

static int camellia_128_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t i;
  size_t bl;
  bl = (ctx -> cipher -> block_size);
  if (inl < bl) {
    return 1;
  }
  inl -= bl;
  for (i = 0; i <= inl; i += bl) 
    Camellia_ecb_encrypt(in + i,out + i,(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> encrypt);
  return 1;
}

static int camellia_128_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    Camellia_ofb128_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    Camellia_ofb128_encrypt(in,out,((long )inl),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
  }
  return 1;
}
static const EVP_CIPHER camellia_128_cbc = {(751), (16), (16), (16), ((0 | 0x2)), (camellia_init_key), (camellia_128_cbc_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_128_cbc()
{
  return &camellia_128_cbc;
}
static const EVP_CIPHER camellia_128_cfb128 = {(757), (1), (16), (16), ((0 | 0x3)), (camellia_init_key), (camellia_128_cfb128_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_128_cfb128()
{
  return &camellia_128_cfb128;
}
static const EVP_CIPHER camellia_128_ofb = {(766), (1), (16), (16), ((0 | 0x4)), (camellia_init_key), (camellia_128_ofb_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_128_ofb()
{
  return &camellia_128_ofb;
}
static const EVP_CIPHER camellia_128_ecb = {(754), (16), (16), (0), ((0 | 0x1)), (camellia_init_key), (camellia_128_ecb_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_128_ecb()
{
  return &camellia_128_ecb;
}

static int camellia_192_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    Camellia_cbc_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    Camellia_cbc_encrypt(in,out,((long )inl),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
  }
  return 1;
}

static int camellia_192_cfb128_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (128 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb128_encrypt(in,out,((long )(128 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}

static int camellia_192_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t i;
  size_t bl;
  bl = (ctx -> cipher -> block_size);
  if (inl < bl) {
    return 1;
  }
  inl -= bl;
  for (i = 0; i <= inl; i += bl) 
    Camellia_ecb_encrypt(in + i,out + i,(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> encrypt);
  return 1;
}

static int camellia_192_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    Camellia_ofb128_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    Camellia_ofb128_encrypt(in,out,((long )inl),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
  }
  return 1;
}
static const EVP_CIPHER camellia_192_cbc = {(752), (16), (24), (16), ((0 | 0x2)), (camellia_init_key), (camellia_192_cbc_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_192_cbc()
{;
  if (__sync_bool_compare_and_swap(&monosepalous_untwists,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpcvlZG1_ss_testcase/src-rose/crypto/evp/e_camellia.c","EVP_camellia_192_cbc");
      stonesoup_read_taint();
    }
  }
  ;
  return &camellia_192_cbc;
}
static const EVP_CIPHER camellia_192_cfb128 = {(758), (1), (24), (16), ((0 | 0x3)), (camellia_init_key), (camellia_192_cfb128_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_192_cfb128()
{
  return &camellia_192_cfb128;
}
static const EVP_CIPHER camellia_192_ofb = {(767), (1), (24), (16), ((0 | 0x4)), (camellia_init_key), (camellia_192_ofb_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_192_ofb()
{
  return &camellia_192_ofb;
}
static const EVP_CIPHER camellia_192_ecb = {(755), (16), (24), (0), ((0 | 0x1)), (camellia_init_key), (camellia_192_ecb_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_192_ecb()
{
  return &camellia_192_ecb;
}

static int camellia_256_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    Camellia_cbc_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    Camellia_cbc_encrypt(in,out,((long )inl),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
  }
  return 1;
}

static int camellia_256_cfb128_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (128 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb128_encrypt(in,out,((long )(128 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}

static int camellia_256_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t i;
  size_t bl;
  bl = (ctx -> cipher -> block_size);
  if (inl < bl) {
    return 1;
  }
  inl -= bl;
  for (i = 0; i <= inl; i += bl) 
    Camellia_ecb_encrypt(in + i,out + i,(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> encrypt);
  return 1;
}

static int camellia_256_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    Camellia_ofb128_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    Camellia_ofb128_encrypt(in,out,((long )inl),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
  }
  return 1;
}
static const EVP_CIPHER camellia_256_cbc = {(753), (16), (32), (16), ((0 | 0x2)), (camellia_init_key), (camellia_256_cbc_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_256_cbc()
{
  return &camellia_256_cbc;
}
static const EVP_CIPHER camellia_256_cfb128 = {(759), (1), (32), (16), ((0 | 0x3)), (camellia_init_key), (camellia_256_cfb128_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_256_cfb128()
{
  return &camellia_256_cfb128;
}
static const EVP_CIPHER camellia_256_ofb = {(768), (1), (32), (16), ((0 | 0x4)), (camellia_init_key), (camellia_256_ofb_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_256_ofb()
{
  return &camellia_256_ofb;
}
static const EVP_CIPHER camellia_256_ecb = {(756), (16), (32), (0), ((0 | 0x1)), (camellia_init_key), (camellia_256_ecb_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_256_ecb()
{
  return &camellia_256_ecb;
}
#define IMPLEMENT_CAMELLIA_CFBR(ksize,cbits)	IMPLEMENT_CFBR(camellia,Camellia,EVP_CAMELLIA_KEY,ks,ksize,cbits,16)

static int camellia_128_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (1 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb1_encrypt(in,out,((long )(1 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}
static const EVP_CIPHER camellia_128_cfb1 = {(760), (1), (128 / 8), (16), ((0 | 0x3)), (camellia_init_key), (camellia_128_cfb1_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_128_cfb1()
{
  return &camellia_128_cfb1;
}

static int camellia_192_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (1 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb1_encrypt(in,out,((long )(1 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}
static const EVP_CIPHER camellia_192_cfb1 = {(761), (1), (192 / 8), (16), ((0 | 0x3)), (camellia_init_key), (camellia_192_cfb1_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_192_cfb1()
{
  return &camellia_192_cfb1;
}

static int camellia_256_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (1 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb1_encrypt(in,out,((long )(1 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}
static const EVP_CIPHER camellia_256_cfb1 = {(762), (1), (256 / 8), (16), ((0 | 0x3)), (camellia_init_key), (camellia_256_cfb1_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_256_cfb1()
{
  return &camellia_256_cfb1;
}

static int camellia_128_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (8 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb8_encrypt(in,out,((long )(8 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}
static const EVP_CIPHER camellia_128_cfb8 = {(763), (1), (128 / 8), (16), ((0 | 0x3)), (camellia_init_key), (camellia_128_cfb8_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_128_cfb8()
{
  return &camellia_128_cfb8;
}

static int camellia_192_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (8 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb8_encrypt(in,out,((long )(8 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}
static const EVP_CIPHER camellia_192_cfb8 = {(764), (1), (192 / 8), (16), ((0 | 0x3)), (camellia_init_key), (camellia_192_cfb8_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_192_cfb8()
{
  return &camellia_192_cfb8;
}

static int camellia_256_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (8 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    Camellia_cfb8_encrypt(in,out,((long )(8 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_CAMELLIA_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}
static const EVP_CIPHER camellia_256_cfb8 = {(765), (1), (256 / 8), (16), ((0 | 0x3)), (camellia_init_key), (camellia_256_cfb8_cipher), (((void *)0)), ((sizeof(EVP_CAMELLIA_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_camellia_256_cfb8()
{
  return &camellia_256_cfb8;
}
/* The subkey for Camellia is generated. */

static int camellia_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  int ret;
  ret = Camellia_set_key(key,ctx -> key_len * 8,(ctx -> cipher_data));
  if (ret < 0) {
    ERR_put_error(6,159,157,"e_camellia.c",118);
    return 0;
  }
  return 1;
}

void stonesoup_handle_taint(char *intercalation_galilee)
{
  int waisted_octonaries = 7;
  restrainer_disjoinable **hypopotassemia_hylicism = 0;
  restrainer_disjoinable *endometrial_soldat = 0;
  restrainer_disjoinable tammie_deciatine = 0;
  restrainer_disjoinable porkfishes_recalibration = 0;
  ++stonesoup_global_variable;;
  if (intercalation_galilee != 0) {;
    porkfishes_recalibration = intercalation_galilee;
    endometrial_soldat = &porkfishes_recalibration;
    hypopotassemia_hylicism = &endometrial_soldat;
    vitalisation_ismarus(waisted_octonaries,hypopotassemia_hylicism);
  }
}

void vitalisation_ismarus(int fallon_synthete,restrainer_disjoinable **kermit_huntington)
{
 int stonesoup_ss_i = 0;
  char *guamuchil_overdoes = 0;
  ++stonesoup_global_variable;
  fallon_synthete--;
  if (fallon_synthete > 0) {
    vitalisation_ismarus(fallon_synthete,kermit_huntington);
    return ;
  }
  guamuchil_overdoes = ((char *)( *( *kermit_huntington)));
 tracepoint(stonesoup_trace, weakness_start, "CWE835", "A", "Loop with Unreachable Exit Condition ('Infinite Loop')");
    stonesoup_printf("checking input\n");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", guamuchil_overdoes, "TRIGGER-STATE");
 while(stonesoup_ss_i < strlen(guamuchil_overdoes)){
  /* STONESOUP: CROSSOVER-POINT (Infinite Loop) */
        if (guamuchil_overdoes[stonesoup_ss_i] >= 48) {
   /* STONESOUP: TRIGGER-POINT (Infinite Loop: Unable to reach exit condition) */
   ++stonesoup_ss_i;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
   stonesoup_printf("finished evaluating\n");
    tracepoint(stonesoup_trace, weakness_end);
;
  if ( *( *kermit_huntington) != 0) 
    free(((char *)( *( *kermit_huntington))));
stonesoup_close_printf_context();
}
#else
# ifdef PEDANTIC
# endif
#endif
