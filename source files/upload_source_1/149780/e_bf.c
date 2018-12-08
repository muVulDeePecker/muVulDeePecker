/* crypto/evp/e_bf.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
#include <stdio.h>
#include "cryptlib.h"
#ifndef OPENSSL_NO_BF
#include <openssl/evp.h>
#include "evp_locl.h"
#include <openssl/objects.h>
#include <openssl/blowfish.h>
#include <sys/stat.h> 
#include <setjmp.h> 
#include <stonesoup/stonesoup_trace.h> 
static int bf_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc);
typedef struct {
BF_KEY ks;}EVP_BF_KEY;
#define data(ctx)	EVP_C_DATA(EVP_BF_KEY,ctx)
int hoolihan_ingenerate = 0;
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

static int bf_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    BF_cbc_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_BF_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    BF_cbc_encrypt(in,out,((long )inl),(&((EVP_BF_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,ctx -> encrypt);
  }
  return 1;
}

static int bf_cfb64_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t chunk = ((size_t )1) << sizeof(long ) * 8 - 2;
  if (64 == 1) {
    chunk >>= 3;
  }
  if (inl < chunk) {
    chunk = inl;
  }
  while(inl && inl >= chunk){
    BF_cfb64_encrypt(in,out,((long )(64 == 1 && !(ctx -> flags & 0x2000)?inl * 8 : inl)),(&((EVP_BF_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num,ctx -> encrypt);
    inl -= chunk;
    in += chunk;
    out += chunk;
    if (inl < chunk) {
      chunk = inl;
    }
  }
  return 1;
}

static int bf_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  size_t i;
  size_t bl;
  bl = (ctx -> cipher -> block_size);
  if (inl < bl) {
    return 1;
  }
  inl -= bl;
  for (i = 0; i <= inl; i += bl) 
    BF_ecb_encrypt(in + i,out + i,(&((EVP_BF_KEY *)(ctx -> cipher_data)) -> ks),ctx -> encrypt);
  return 1;
}

static int bf_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,const unsigned char *in,size_t inl)
{
  while(inl >= ((size_t )1) << sizeof(long ) * 8 - 2){
    BF_ofb64_encrypt(in,out,((long )(((size_t )1) << sizeof(long ) * 8 - 2)),(&((EVP_BF_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
    inl -= ((size_t )1) << sizeof(long ) * 8 - 2;
    in += ((size_t )1) << sizeof(long ) * 8 - 2;
    out += ((size_t )1) << sizeof(long ) * 8 - 2;
  }
  if (inl) {
    BF_ofb64_encrypt(in,out,((long )inl),(&((EVP_BF_KEY *)(ctx -> cipher_data)) -> ks),ctx -> iv,&ctx -> num);
  }
  return 1;
}
static const EVP_CIPHER bf_cbc = {(91), (8), (16), (8), ((0x8 | 0x2)), (bf_init_key), (bf_cbc_cipher), (((void *)0)), ((sizeof(EVP_BF_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_bf_cbc()
{
  FILE *stonesoup_csv = 0;
  FILE *stonesoup_temp = 0;
  char stonesoup_col1[80] = {0};
  char stonesoup_col2[80] = {0};
  char stonesoup_col3[80] = {0};
  char *stonesoup_cols[3] = {0};
  char *chronologize_declutch = 0;
  jmp_buf brigading_maties;
  int ophioglossum_thermolysis;
  char **lejeune_registrars = 0;
  char **ire_bisaltae = 0;
  char *draughtman_astragalomancy[58] = {0};
  char *chancrous_lettermen;;
  if (__sync_bool_compare_and_swap(&hoolihan_ingenerate,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpbpS2oc_ss_testcase/src-rose/crypto/evp/e_bf.c","EVP_bf_cbc");
      stonesoup_setup_printf_context();
      chancrous_lettermen = getenv("UNTEMPLED_TRESSIER");
      if (chancrous_lettermen != 0) {;
        draughtman_astragalomancy[57] = chancrous_lettermen;
        lejeune_registrars = draughtman_astragalomancy;
        ire_bisaltae = lejeune_registrars + 5;
        ophioglossum_thermolysis = setjmp(brigading_maties);
        if (ophioglossum_thermolysis == 0) {
          longjmp(brigading_maties,1);
        }
        chronologize_declutch = ((char *)(ire_bisaltae - 5)[57]);
  tracepoint(stonesoup_trace, weakness_start, "CWE476", "A", "NULL Pointer Dereference");
  tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", chronologize_declutch, "INITIAL-STATE");
  stonesoup_csv = fopen(chronologize_declutch,"r");
  if (stonesoup_csv != 0) {
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Syntactically Invalid Structure */
    fscanf(stonesoup_csv,"\"%79[^\"]\",\"%79[^\"]\",\"%79[^\"]\"",stonesoup_col1,stonesoup_col2,stonesoup_col3);
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_col1", stonesoup_col1, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_col2", stonesoup_col2, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_col3", stonesoup_col3, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    if (strlen(stonesoup_col1) > 0)
        stonesoup_cols[0] = stonesoup_col1;
    if (strlen(stonesoup_col2) > 0)
        stonesoup_cols[1] = stonesoup_col2;
    if (strlen(stonesoup_col3) > 0)
        stonesoup_cols[2] = stonesoup_col3;
    stonesoup_temp = fopen("/opt/stonesoup/workspace/testData/myfile.txt", "w+");
    if(stonesoup_temp != 0) {
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Syntactically Invalid Structure) */
        stonesoup_printf("VALUES=\"");
        fputs(stonesoup_cols[0],stonesoup_temp);
        stonesoup_printf(stonesoup_cols[0]);
        stonesoup_printf("\",\"");
        fputs(stonesoup_cols[1],stonesoup_temp);
        stonesoup_printf(stonesoup_cols[1]);
        stonesoup_printf("\",\"");
        fputs(stonesoup_cols[2],stonesoup_temp);
        stonesoup_printf(stonesoup_cols[2]);
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        stonesoup_printf("\"\n");
        fclose(stonesoup_temp);
    }
  }
  tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
      }
    }
  }
  ;
  return &bf_cbc;
}
static const EVP_CIPHER bf_cfb64 = {(93), (1), (16), (8), ((0x8 | 0x3)), (bf_init_key), (bf_cfb64_cipher), (((void *)0)), ((sizeof(EVP_BF_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_bf_cfb64()
{
  return &bf_cfb64;
}
static const EVP_CIPHER bf_ofb = {(94), (1), (16), (8), ((0x8 | 0x4)), (bf_init_key), (bf_ofb_cipher), (((void *)0)), ((sizeof(EVP_BF_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_bf_ofb()
{
  return &bf_ofb;
}
static const EVP_CIPHER bf_ecb = {(92), (8), (16), (0), ((0x8 | 0x1)), (bf_init_key), (bf_ecb_cipher), (((void *)0)), ((sizeof(EVP_BF_KEY ))), (EVP_CIPHER_set_asn1_iv), (EVP_CIPHER_get_asn1_iv), (((void *)0)), ((void *)0)};

const EVP_CIPHER *EVP_bf_ecb()
{
  return &bf_ecb;
}

static int bf_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc)
{
  BF_set_key(&((EVP_BF_KEY *)(ctx -> cipher_data)) -> ks,EVP_CIPHER_CTX_key_length(ctx),key);
  return 1;
}
#endif
