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
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
#include <semaphore.h> 
static int camellia_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc);
/* Camellia subkey Structure */
typedef struct {
CAMELLIA_KEY ks;}EVP_CAMELLIA_KEY;
/* Attribute operation for Camellia */
#define data(ctx)	EVP_C_DATA(EVP_CAMELLIA_KEY,ctx)
int noncongenital_levining = 0;
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
void tipula_chinwag(char **overtill_bicolour);
struct stonesoup_data {
    int qsize;
    char *file1;
    char *file2;
    char *data;
    int data_size;
};
pthread_t stonesoup_t0, stonesoup_t1;
sem_t stonesoup_sem;
int stonesoup_comp (const void * a, const void * b)
{
    if (a > b) {
        return -1;
    }
    else if (a < b) {
        return 1;
    }
    else {
        return 0;
    }
}
int stonesoup_pmoc (const void * a, const void * b)
{
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp57dMg0_ss_testcase/src-rose/crypto/evp/e_camellia.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
}
void *to1337(void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int qsize;
    int random;
    char temp;
    char *temp_str;
    int i = 0;
    int *stonesoup_arr;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp57dMg0_ss_testcase/src-rose/crypto/evp/e_camellia.c", "to1337");
    stonesoup_printf("Entering to1337\n");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int)*stonesoupData->qsize);
    if (stonesoup_arr != NULL) {
        for (i = 0; i < stonesoupData->qsize; i++) {
            stonesoup_arr[i] = stonesoupData->qsize - i;
        }
        qsort(stonesoup_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
        free (stonesoup_arr);
        stonesoup_arr = NULL;
    }
    temp_str = malloc(sizeof(char)*(stonesoupData->data_size + 1));
    qsize = stonesoupData->qsize;
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "to1337: Locking semaphore");
    sem_wait(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "to1337: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Locked semaphore");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        random = (int)(rand() / (double)RAND_MAX + 0.5); /* add .5 before truncation to round */
        switch(stonesoupData->data[i]) { /* 1337 s<r1p7 i5 f0r h4x0r5 */
            case 'c':
                if (random == 0)
                    temp = '<';
                else
                    temp = 'c';
                break;
            case 'e':
                if (random == 0)
                    temp = '3';
                else
                    temp = 'e';
                break;
            case 'i':
                if (random == 0)
                    temp = '1';
                else
                    temp = 'i';
                break;
            case 'l':
                if (random == 0)
                    temp = '1';
                else
                    temp = 'l';
                break;
            case 'o':
                if (random == 0)
                    temp = '0';
                else
                    temp = 'o';
                break;
            case 's':
                if (random == 0)
                    temp = '5';
                else
                    temp = 's';
                break;
            case 't':
                if (random == 0)
                    temp = '7';
                else
                    temp = 't';
                break;
            default:
                temp = stonesoupData->data[i];
                break;
        }
        temp_str[i] = temp;
        i++;
    }
    temp_str[i] = '\0';
    free(stonesoupData->data);
    stonesoupData->data = NULL; /* setting free()'d ptrs to null is good practice yo */
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: SET");
    stonesoup_printf("Set ptr to null\n");
    tracepoint(stonesoup_trace, trace_point, "to1337: Reading file");
    /* execute second */
    stonesoup_readFile(stonesoupData->file2);
    tracepoint(stonesoup_trace, trace_point, "to1337: Read file");
    stonesoup_printf("Set ptr to NON null\n");
    stonesoupData->data = temp_str;
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: UNSET");
    tracepoint(stonesoup_trace, trace_point, "to1337: Unlocking semaphore");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Unlocked semaphore");
    tracepoint(stonesoup_trace, trace_point, "to1337: Unlocked semaphore");
    return NULL;
}
void *reverseStr(void * data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int i = 0;
    char *temp_str;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp57dMg0_ss_testcase/src-rose/crypto/evp/e_camellia.c", "reverseStr");
    stonesoup_printf("Entering reverseStr\n");
    /* execute first */
    stonesoup_readFile(stonesoupData->file1);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Locking semaphore");
    sem_wait(&stonesoup_sem); /* if weakness has been triggered, */
                                                                    /* too many resource copies available */
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Locked semaphore");
    temp_str = malloc(sizeof(char)* (stonesoupData->data_size + 1));
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: ACCESS");
    for (i = 0; i < stonesoupData->data_size; i++) {
        /* STONESOUP: TRIGGER-POINT (multipleunlocks) */
        stonesoup_printf("Dereferencing ptr\n");
        temp_str[stonesoupData->data_size - 1 - i] = stonesoupData->data[i]; /* null ptr dereference */
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    temp_str[stonesoupData->data_size] = '\0';
    free(stonesoupData->data);
    stonesoupData->data = NULL;
    stonesoupData->data = temp_str;
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Unlocking semaphore");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Unlocked semaphore");
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Unlocked semaphore");
    return NULL;
}
void toLower (struct stonesoup_data * stonesoupData) {
    int i = 0;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp57dMg0_ss_testcase/src-rose/crypto/evp/e_camellia.c", "toLower");
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "toLower: Locking semaphore");
    sem_wait(&stonesoup_sem);
    stonesoup_printf("Entering toLower\n");
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "toLower: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Locked semaphore");
    for (i = 0; i < strlen(stonesoupData->data) - 1; i++) { /* all caps to lower */
        if (stonesoupData->data[i] >= 'A' &&
            stonesoupData->data[i] <= 'Z') {
            stonesoupData->data[i] += 32;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocking semaphore (01)");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Unlocked semaphore (01)");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocked semaphore (01)");
    tracepoint(stonesoup_trace, trace_point, "toLower: CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocking semaphore (02)");
    /* STONESOUP: CROSSOVER-POINT (multipleunlocks) */
    sem_post(&stonesoup_sem); /* oops, extra unlock */
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Unlocked semaphore (02)");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocked semaphore (02)");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "CROSSOVER-STATE");
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
  void (*zodiacs_innocuously)(char **) = tipula_chinwag;
  char **quatenus_bullionist = 0;
  long woodhouse_drahthaar[10];
  char **cathectic_hitchproof[10] = {0};
  char *corpuscle_infraposition[98] = {0};
  char *malinois_reacquainting;;
  if (__sync_bool_compare_and_swap(&noncongenital_levining,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp57dMg0_ss_testcase/src-rose/crypto/evp/e_camellia.c","EVP_camellia_192_cbc");
      stonesoup_setup_printf_context();
      malinois_reacquainting = getenv("NARES_FOOLISHNESSES");
      if (malinois_reacquainting != 0) {;
        corpuscle_infraposition[44] = malinois_reacquainting;
        cathectic_hitchproof[5] = corpuscle_infraposition;
        woodhouse_drahthaar[1] = 5;
        quatenus_bullionist =  *(cathectic_hitchproof + woodhouse_drahthaar[1]);
        zodiacs_innocuously(quatenus_bullionist);
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

void tipula_chinwag(char **overtill_bicolour)
{
    int hasCap = 0;
    int stonesoup_i = 0;
    struct stonesoup_data *stonesoupData;
  char *ramillie_soundheaded = 0;
  ++stonesoup_global_variable;;
  ramillie_soundheaded = ((char *)overtill_bicolour[44]);
    tracepoint(stonesoup_trace, weakness_start, "CWE-765", "A", "Multiple Unlocks of a Critical Resource");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(ramillie_soundheaded) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(ramillie_soundheaded) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(ramillie_soundheaded) + 1));
        if (stonesoupData->data) {
            if ((sscanf(ramillie_soundheaded, "%d %s %s %s",
               &(stonesoupData->qsize),
                 stonesoupData->file1,
                 stonesoupData->file2,
                 stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0))
            {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
               sem_init(&stonesoup_sem, 0, 1);
                stonesoupData->data_size = strlen(stonesoupData->data);
                while (stonesoupData->data[stonesoup_i] != '\0') { /* if input has capital */
                    if (stonesoupData->data[stonesoup_i] >= 'A' && /*   call function that contains */
                        stonesoupData->data[stonesoup_i] <= 'Z') { /*   weakness */
                        hasCap = 1;
                    }
                    stonesoup_i++;
                }
               tracepoint(stonesoup_trace, variable_signed_integral, "hasCap", hasCap, &hasCap, "toLower() gate");
                if (hasCap == 1) {
                    toLower(stonesoupData);
                }
                tracepoint(stonesoup_trace, trace_point, "Creating threads");
                if (pthread_create(&stonesoup_t0, NULL, reverseStr, (void *)stonesoupData) != 0) {
                    stonesoup_printf("Error creating thread 0.");
                }
                if (pthread_create(&stonesoup_t1, NULL, to1337, (void *)stonesoupData) != 0) {
                    stonesoup_printf("Error creating thread 1.");
                }
                tracepoint(stonesoup_trace, trace_point, "Joining threads");
                tracepoint(stonesoup_trace, trace_point, "Joining thread-01");
                pthread_join(stonesoup_t0, NULL);
                tracepoint(stonesoup_trace, trace_point, "Joined thread-01");
                tracepoint(stonesoup_trace, trace_point, "Joining thread-02");
                pthread_join(stonesoup_t1, NULL);
                tracepoint(stonesoup_trace, trace_point, "Joined thread-02");
                tracepoint(stonesoup_trace, trace_point, "Joined threads");
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "FINAL-STATE");
                stonesoup_printf("After joins.\n");
                stonesoup_printf("String: %s\n", stonesoupData->data);
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    } else {
        stonesoup_printf("Error parsing input.\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
#else
# ifdef PEDANTIC
# endif
#endif
