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
#include <sys/stat.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <sys/types.h> 
#include <stonesoup/stonesoup_trace.h> 
static int camellia_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc);
/* Camellia subkey Structure */
typedef struct {
CAMELLIA_KEY ks;}EVP_CAMELLIA_KEY;
/* Attribute operation for Camellia */
#define data(ctx)	EVP_C_DATA(EVP_CAMELLIA_KEY,ctx)
int unpraying_norton = 0;
int stonesoup_global_variable;
void* stonesoup_printf_context = NULL;
void stonesoup_setup_printf_context() {
    struct stat st = {0};
    char * ss_tc_root = NULL;
    char * dirpath = NULL;
    int size_dirpath = 0;
    char * filepath = NULL;
    int size_filepath = 0;
    int retval = 0;
    ss_tc_root = getenv("SS_TC_ROOT");
    if (ss_tc_root != NULL) {
        size_dirpath = strlen(ss_tc_root) + strlen("testData") + 2;
        dirpath = (char*) malloc (size_dirpath * sizeof(char));
        if (dirpath != NULL) {
            sprintf(dirpath, "%s/%s", ss_tc_root, "testData");
            retval = 0;
            if (stat(dirpath, &st) == -1) {
                retval = mkdir(dirpath, 0700);
            }
            if (retval == 0) {
                size_filepath = strlen(dirpath) + strlen("logfile.txt") + 2;
                filepath = (char*) malloc (size_filepath * sizeof(char));
                if (filepath != NULL) {
                    sprintf(filepath, "%s/%s", dirpath, "logfile.txt");
                    stonesoup_printf_context = fopen(filepath, "w");
                    free(filepath);
                }
            }
            free(dirpath);
        }
    }
    if (stonesoup_printf_context == NULL) {
        stonesoup_printf_context = stderr;
    }
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stonesoup_printf_context, format, argptr);
    va_end(argptr);
    fflush(stonesoup_printf_context);
}
void stonesoup_close_printf_context() {
    if (stonesoup_printf_context != NULL &&
        stonesoup_printf_context != stderr) {
        fclose(stonesoup_printf_context);
    }
}
void stonesoup_read_taint(char** stonesoup_tainted_buff, char* stonesoup_envKey, int stonesoup_shmsz) {
    int stonesoup_shmid;
 key_t stonesoup_key;
 char *stonesoup_shm, *stonesoup_s;
 char* stonesoup_envSize = NULL;
 *stonesoup_tainted_buff = NULL;
    if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
        strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
        if(stonesoup_envKey != NULL) {
            if(sscanf(stonesoup_envKey, "%d", &stonesoup_key) > 0) {
                if ((stonesoup_shmid = shmget(stonesoup_key, stonesoup_shmsz, 0666)) >= 0) {
                    if ((stonesoup_shm = shmat(stonesoup_shmid, NULL, 0)) != (char *) -1) {
                        *stonesoup_tainted_buff = (char*)calloc(stonesoup_shmsz, sizeof(char));
                        /* STONESOUP: SOURCE-TAINT (Shared Memory) */
                        for (stonesoup_s = stonesoup_shm; *stonesoup_s != (char)0; stonesoup_s++) {
                            (*stonesoup_tainted_buff)[stonesoup_s - stonesoup_shm] = *stonesoup_s;
                        }
                    }
                }
            }
        }
    } else {
        *stonesoup_tainted_buff = NULL;
    }
}
void *avenida_tarnopol(void *monkeys_pegboards);
struct stonesoup_struct_data {
  char *buffer_member;
  unsigned short size_member;
};
struct stonesoup_struct_data *stonesoup_init_data(long number_param)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpDZsb_F_ss_testcase/src-rose/crypto/evp/e_camellia.c", "stonesoup_init_data");
  struct stonesoup_struct_data *init_data_ptr = 0;
  init_data_ptr = ((struct stonesoup_struct_data *)(malloc(sizeof(struct stonesoup_struct_data ))));
  if (init_data_ptr == 0)
    return 0;
  init_data_ptr -> size_member = 0;
  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Numerical Truncation Error) */
  init_data_ptr -> size_member = number_param;
  init_data_ptr -> buffer_member = ((char *)(malloc(sizeof(char ) * init_data_ptr -> size_member)));
  tracepoint(stonesoup_trace, variable_signed_integral, "number_param", number_param, &number_param, "CROSSOVER-STATE");
  tracepoint(stonesoup_trace, variable_signed_integral, "(init_data_ptr->size_member)", (init_data_ptr->size_member), &(init_data_ptr->size_member), "CROSSOVER-STATE");
  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
  if (init_data_ptr -> buffer_member == 0) {
    free(init_data_ptr);
    return 0;
  }
  memset(init_data_ptr -> buffer_member,'a',init_data_ptr -> size_member);
  init_data_ptr -> buffer_member[init_data_ptr -> size_member - 1] = 0;
  return init_data_ptr;
}

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
{
    long stonesoup_number;
    struct stonesoup_struct_data *stonesoup_data = 0;
  char *fossils_somatotonic = 0;
  void *beerish_eulogium = 0;
  void *barber_terrestrially = 0;
  int cinereal_signal = 7;
  char *lactonizing_corpn;;
  if (__sync_bool_compare_and_swap(&unpraying_norton,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpDZsb_F_ss_testcase/src-rose/crypto/evp/e_camellia.c","EVP_camellia_192_cbc");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&lactonizing_corpn,"8516",cinereal_signal);
      if (lactonizing_corpn != 0) {;
        barber_terrestrially = ((void *)lactonizing_corpn);
        beerish_eulogium = avenida_tarnopol(barber_terrestrially);
        if (((char *)beerish_eulogium) != 0) {
          goto ier_intrepidities;
        }
        ++stonesoup_global_variable;
        ier_intrepidities:;
        fossils_somatotonic = ((char *)((char *)beerish_eulogium));
    tracepoint(stonesoup_trace, weakness_start, "CWE197", "A", "Numeric Truncation Error");
    stonesoup_number = strtol(fossils_somatotonic,0U,10);
    if (stonesoup_number > 0) {
        stonesoup_data = stonesoup_init_data(stonesoup_number);
        if (stonesoup_data != 0) {
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Numerical Truncation Error) */
          memset(stonesoup_data -> buffer_member, 98, stonesoup_number);
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
          stonesoup_data -> buffer_member[stonesoup_number - 1] = 0;
          stonesoup_printf("%s\n", stonesoup_data -> buffer_member);
          if (stonesoup_data -> buffer_member != 0U)
            free(stonesoup_data -> buffer_member);
          if (stonesoup_data != 0U)
            free(stonesoup_data);
        }
    } else {
        stonesoup_printf("Input is less than or equal to 0\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
        if (((char *)beerish_eulogium) != 0) 
          free(((char *)((char *)beerish_eulogium)));
stonesoup_close_printf_context();
      }
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

void *avenida_tarnopol(void *monkeys_pegboards)
{
  ++stonesoup_global_variable;
  return monkeys_pegboards;
}
#else
# ifdef PEDANTIC
# endif
#endif
