/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include "eng_int.h"
/* The type of the items in the table */
#include <sys/stat.h> 
#include <stonesoup/stonesoup_trace.h> 
typedef struct st_engine_pile {
/* The 'nid' of this algorithm/mode */
int nid;
/* ENGINEs that implement this algorithm/mode. */
struct stack_st_ENGINE *sk;
/* The default ENGINE to perform this algorithm/mode. */
ENGINE *funct;
/* Zero if 'sk' is newer than the cached 'funct', non-zero otherwise */
int uptodate;}ENGINE_PILE;

struct lhash_st_ENGINE_PILE 
{
  int dummy;
}
;
/* The type exposed in eng_int.h */

struct st_engine_table 
{
  struct lhash_st_ENGINE_PILE piles;
/* ENGINE_TABLE */
}
;
typedef struct st_engine_pile_doall {
engine_table_doall_cb *cb;
void *arg;}ENGINE_PILE_DOALL;
/* Global flags (ENGINE_TABLE_FLAG_***). */
static unsigned int table_flags = 0;
/* API function manipulating 'table_flags' */
int makars_mayan = 0;
int stonesoup_global_variable;
typedef char *tegument_unpushed;
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
tegument_unpushed imparisyllabic_ottillia(tegument_unpushed considerably_overattenuate);
int stonesoup_476_global_variable = 0;
int stonesoup_isalnum(int c)
{
  if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57)) {
    return 1;
  }
  return 0;
}

unsigned int ENGINE_get_table_flags()
{
  return table_flags;
}

void ENGINE_set_table_flags(unsigned int flags)
{
  table_flags = flags;
}
/* Internal functions for the "piles" hash table */

static unsigned long engine_pile_hash(const ENGINE_PILE *c)
{
  return (c -> nid);
}

static int engine_pile_cmp(const ENGINE_PILE *a,const ENGINE_PILE *b)
{
  return a -> nid - b -> nid;
}

static unsigned long engine_pile_LHASH_HASH(const void *arg)
{
  const ENGINE_PILE *a = arg;
  return engine_pile_hash(a);
}

static int engine_pile_LHASH_COMP(const void *arg1,const void *arg2)
{
  const ENGINE_PILE *a = arg1;
  const ENGINE_PILE *b = arg2;
  return engine_pile_cmp(a,b);
}

static int int_table_check(ENGINE_TABLE **t,int create)
{
  struct lhash_st_ENGINE_PILE *lh;
  if ( *t) {
    return 1;
  }
  if (!create) {
    return 0;
  }
  if ((lh = ((struct lhash_st_ENGINE_PILE *)(lh_new(engine_pile_LHASH_HASH,engine_pile_LHASH_COMP)))) == ((void *)0)) {
    return 0;
  }
   *t = ((ENGINE_TABLE *)lh);
  return 1;
}
/* Privately exposed (via eng_int.h) functions for adding and/or removing
 * ENGINEs from the implementation table */

int engine_table_register(ENGINE_TABLE **table,ENGINE_CLEANUP_CB *cleanup,ENGINE *e,const int *nids,int num_nids,int setdefault)
{
  int ret = 0;
  int added = 0;
  ENGINE_PILE tmplate;
  ENGINE_PILE *fnd;
  CRYPTO_lock(1 | 8,30,"eng_table.c",135);
  if (!( *table)) {
    added = 1;
  }
  if (!int_table_check(table,1)) {
    goto end;
  }
  if (added) {
/* The cleanup callback needs to be added */
    engine_cleanup_add_first(cleanup);
  }
  while(num_nids--){
    tmplate . nid =  *nids;
    fnd = ((ENGINE_PILE *)(lh_retrieve(((_LHASH *)((void *)(&( *table) -> piles))),((void *)(&tmplate)))));
    if (!fnd) {
      fnd = (CRYPTO_malloc(((int )(sizeof(ENGINE_PILE ))),"eng_table.c",149));
      if (!fnd) {
        goto end;
      }
      fnd -> uptodate = 1;
      fnd -> nid =  *nids;
      fnd -> sk = ((struct stack_st_ENGINE *)(sk_new_null()));
      if (!fnd -> sk) {
        CRYPTO_free(fnd);
        goto end;
      }
      fnd -> funct = ((void *)0);
      (void )((ENGINE_PILE *)(lh_insert(((_LHASH *)((void *)(&( *table) -> piles))),((void *)(1?fnd : ((ENGINE_PILE *)0))))));
    }
/* A registration shouldn't add duplciate entries */
    (void )((ENGINE *)(sk_delete_ptr(((_STACK *)(1?fnd -> sk : ((struct stack_st_ENGINE *)0))),((void *)(1?e : ((ENGINE *)0))))));
/* if 'setdefault', this ENGINE goes to the head of the list */
    if (!sk_push(((_STACK *)((1?fnd -> sk : ((struct stack_st_ENGINE *)0)))),((void *)((1?e : ((ENGINE *)0)))))) {
      goto end;
    }
/* "touch" this ENGINE_PILE */
    fnd -> uptodate = 0;
    if (setdefault) {
      if (!engine_unlocked_init(e)) {
        ERR_put_error(38,184,109,"eng_table.c",174);
        goto end;
      }
      if (fnd -> funct) {
        engine_unlocked_finish(fnd -> funct,0);
      }
      fnd -> funct = e;
      fnd -> uptodate = 1;
    }
    nids++;
  }
  ret = 1;
  end:
  CRYPTO_lock(2 | 8,30,"eng_table.c",186);
  return ret;
}

static void int_unregister_cb_doall_arg(ENGINE_PILE *pile,ENGINE *e)
{
  int n;
/* Iterate the 'c->sk' stack removing any occurance of 'e' */
  while((n = sk_find(((_STACK *)((1?pile -> sk : ((struct stack_st_ENGINE *)0)))),((void *)((1?e : ((ENGINE *)0)))))) >= 0){
    (void )((ENGINE *)(sk_delete(((_STACK *)(1?pile -> sk : ((struct stack_st_ENGINE *)0))),n)));
    pile -> uptodate = 0;
  }
  if (pile -> funct == e) {
    engine_unlocked_finish(e,0);
    pile -> funct = ((void *)0);
  }
}

static void int_unregister_cb_LHASH_DOALL_ARG(void *arg1,void *arg2)
{
  ENGINE_PILE *a = arg1;
  ENGINE *b = arg2;
  int_unregister_cb_doall_arg(a,b);
}

void engine_table_unregister(ENGINE_TABLE **table,ENGINE *e)
{
  CRYPTO_lock(1 | 8,30,"eng_table.c",208);
  if (int_table_check(table,0)) {
    lh_doall_arg(((_LHASH *)((void *)(&( *table) -> piles))),int_unregister_cb_LHASH_DOALL_ARG,((void *)(1?e : ((ENGINE *)0))));
  }
  CRYPTO_lock(2 | 8,30,"eng_table.c",213);
}

static void int_cleanup_cb_doall(ENGINE_PILE *p)
{
  sk_free(((_STACK *)(1?p -> sk : ((struct stack_st_ENGINE *)0))));
  if (p -> funct) {
    engine_unlocked_finish(p -> funct,0);
  }
  CRYPTO_free(p);
}

static void int_cleanup_cb_LHASH_DOALL(void *arg)
{
  char *stonesoup_second_buff = 0;
  int stonesoup_size = 0;
  char *isophane_duikers = 0;
  int insessorial_bahutu;
  int neoteny_shynesses;
  tegument_unpushed levining_gillaroo = 0;
  tegument_unpushed legendarily_reposal = 0;
  char *greatest_familiarly;
  ENGINE_PILE *a = arg;
  if (__sync_bool_compare_and_swap(&makars_mayan,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpDXyZrL_ss_testcase/src-rose/crypto/engine/eng_table.c","int_cleanup_cb_LHASH_DOALL");
      stonesoup_setup_printf_context();
      greatest_familiarly = getenv("DISHEVELLING_TESTAMENTATION");
      if (greatest_familiarly != 0) {;
        legendarily_reposal = greatest_familiarly;
        levining_gillaroo = imparisyllabic_ottillia(legendarily_reposal);
        neoteny_shynesses = 5;
        while(1 == 1){
          neoteny_shynesses = neoteny_shynesses * 2;
          neoteny_shynesses = neoteny_shynesses + 2;
          if (neoteny_shynesses > 1000) {
            break; 
          }
        }
        insessorial_bahutu = neoteny_shynesses;
        isophane_duikers = ((char *)levining_gillaroo);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "D", "NULL Pointer Dereference");
      while(stonesoup_isalnum(isophane_duikers[stonesoup_size]) && stonesoup_size < strlen(isophane_duikers)){
        ++stonesoup_size;
      }
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Null Pointer Dereference) */
      if (stonesoup_size != strlen(isophane_duikers)) {
        isophane_duikers = 0;
      }
      tracepoint(stonesoup_trace, variable_address, "STONESOUP_TAINT_SOURCE", isophane_duikers, "CROSSOVER-STATE");
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      stonesoup_second_buff = malloc((stonesoup_size + 1) * sizeof(char ));
      if (stonesoup_second_buff == 0) {
        stonesoup_printf("Error: Failed to allocate memory\n");
        exit(1);
      }
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference) */
      strcpy(stonesoup_second_buff,isophane_duikers);
      stonesoup_476_global_variable = strlen(stonesoup_second_buff);
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      ++stonesoup_476_global_variable;
      if (stonesoup_second_buff != 0) {
        free(stonesoup_second_buff);
      }
      stonesoup_printf("String contains only alpha numeric characters\n");
      tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
      }
    }
  }
  int_cleanup_cb_doall(a);
}

void engine_table_cleanup(ENGINE_TABLE **table)
{
  CRYPTO_lock(1 | 8,30,"eng_table.c",227);
  if ( *table) {
    lh_doall(((_LHASH *)((void *)(&( *table) -> piles))),int_cleanup_cb_LHASH_DOALL);
    lh_free(((_LHASH *)((void *)(&( *table) -> piles))));
     *table = ((void *)0);
  }
  CRYPTO_lock(2 | 8,30,"eng_table.c",235);
}
/* return a functional reference for a given 'nid' */
#ifndef ENGINE_TABLE_DEBUG

ENGINE *engine_table_select(ENGINE_TABLE **table,int nid)
#else
#endif
{
  ENGINE *ret = ((void *)0);
  ENGINE_PILE tmplate;
  ENGINE_PILE *fnd = ((void *)0);
  int initres;
  int loop = 0;
  if (!( *table)) {
#ifdef ENGINE_TABLE_DEBUG
#endif
    return ((void *)0);
  }
  ERR_set_mark();
  CRYPTO_lock(1 | 8,30,"eng_table.c",258);
/* Check again inside the lock otherwise we could race against cleanup
	 * operations. But don't worry about a fprintf(stderr). */
  if (!int_table_check(table,0)) {
    goto end;
  }
  tmplate . nid = nid;
  fnd = ((ENGINE_PILE *)(lh_retrieve(((_LHASH *)((void *)(&( *table) -> piles))),((void *)(&tmplate)))));
  if (!fnd) {
    goto end;
  }
  if (fnd -> funct && engine_unlocked_init(fnd -> funct)) {
#ifdef ENGINE_TABLE_DEBUG
#endif
    ret = fnd -> funct;
    goto end;
  }
  if (fnd -> uptodate) {
    ret = fnd -> funct;
    goto end;
  }
  trynext:
  ret = ((ENGINE *)(sk_value(((_STACK *)((1?fnd -> sk : ((struct stack_st_ENGINE *)0)))),loop++)));
  if (!ret) {
#ifdef ENGINE_TABLE_DEBUG
#endif
    goto end;
  }
/* Try to initialise the ENGINE? */
  if (ret -> funct_ref > 0 || !(table_flags & ((unsigned int )0x0001))) {
    initres = engine_unlocked_init(ret);
  }
  else {
    initres = 0;
  }
  if (initres) {
/* Update 'funct' */
    if (fnd -> funct != ret && engine_unlocked_init(ret)) {
/* If there was a previous default we release it. */
      if (fnd -> funct) {
        engine_unlocked_finish(fnd -> funct,0);
      }
      fnd -> funct = ret;
#ifdef ENGINE_TABLE_DEBUG
#endif
    }
#ifdef ENGINE_TABLE_DEBUG
#endif
    goto end;
  }
  goto trynext;
  end:
/* If it failed, it is unlikely to succeed again until some future
	 * registrations have taken place. In all cases, we cache. */
  if (fnd) {
    fnd -> uptodate = 1;
  }
#ifdef ENGINE_TABLE_DEBUG
#endif
  CRYPTO_lock(2 | 8,30,"eng_table.c",328);
/* Whatever happened, any failed init()s are not failures in this
	 * context, so clear our error state. */
  ERR_pop_to_mark();
  return ret;
}
/* Table enumeration */

static void int_cb_doall_arg(ENGINE_PILE *pile,ENGINE_PILE_DOALL *dall)
{
  (dall -> cb)(pile -> nid,pile -> sk,pile -> funct,dall -> arg);
}

static void int_cb_LHASH_DOALL_ARG(void *arg1,void *arg2)
{
  ENGINE_PILE *a = arg1;
  ENGINE_PILE_DOALL *b = arg2;
  int_cb_doall_arg(a,b);
}

void engine_table_doall(ENGINE_TABLE *table,engine_table_doall_cb *cb,void *arg)
{
  ENGINE_PILE_DOALL dall;
  dall . cb = cb;
  dall . arg = arg;
  lh_doall_arg(((_LHASH *)((void *)(&table -> piles))),int_cb_LHASH_DOALL_ARG,((void *)(&dall)));
}

tegument_unpushed imparisyllabic_ottillia(tegument_unpushed considerably_overattenuate)
{
  ++stonesoup_global_variable;
  return considerably_overattenuate;
}
