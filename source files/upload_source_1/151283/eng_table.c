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
#include <mongoose.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <sys/stat.h> 
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
int pinang_ada = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *jotham_telesthesia);
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
struct stonesoup_struct_data {
  char *buffer_member;
  unsigned short size_member;
};
struct stonesoup_struct_data *stonesoup_init_data(long number_param)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpi84Y68_ss_testcase/src-rose/crypto/engine/eng_table.c", "stonesoup_init_data");
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
  ENGINE_PILE *a = arg;
  if (__sync_bool_compare_and_swap(&pinang_ada,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpi84Y68_ss_testcase/src-rose/crypto/engine/eng_table.c","int_cleanup_cb_LHASH_DOALL");
      stonesoup_read_taint();
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

void stonesoup_handle_taint(char *jotham_telesthesia)
{
    long stonesoup_number;
    struct stonesoup_struct_data *stonesoup_data = 0;
  char *wagon_cheapened = 0;
  int dryopians_lipkin;
  int kajeputs_slugger;
  char *catamnestic_disillusive = 0;
  int *invariableness_samydaceae = 0;
  int nosy_guirlande;
  char *empiricists_anemones[10] = {0};
  int propoundment_saxicavous = 0;
  char *twitty_onionet = 0;
  ++stonesoup_global_variable;;
  if (jotham_telesthesia != 0) {;
    propoundment_saxicavous = ((int )(strlen(jotham_telesthesia)));
    twitty_onionet = ((char *)(malloc(propoundment_saxicavous + 1)));
    if (twitty_onionet == 0) {
      stonesoup_printf("Error: Failed to allocate memory\n");
      exit(1);
    }
    memset(twitty_onionet,0,propoundment_saxicavous + 1);
    memcpy(twitty_onionet,jotham_telesthesia,propoundment_saxicavous);
    if (jotham_telesthesia != 0) 
      free(((char *)jotham_telesthesia));
    nosy_guirlande = 5;
    invariableness_samydaceae = &nosy_guirlande;
    empiricists_anemones[ *invariableness_samydaceae] = twitty_onionet;
    catamnestic_disillusive = empiricists_anemones[ *invariableness_samydaceae];
    kajeputs_slugger = 5;
    while(1 == 1){
      kajeputs_slugger = kajeputs_slugger * 2;
      kajeputs_slugger = kajeputs_slugger + 2;
      if (kajeputs_slugger > 1000) {
        break; 
      }
    }
    dryopians_lipkin = kajeputs_slugger;
    wagon_cheapened = ((char *)catamnestic_disillusive);
    tracepoint(stonesoup_trace, weakness_start, "CWE197", "A", "Numeric Truncation Error");
    stonesoup_number = strtol(wagon_cheapened,0U,10);
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
    if (catamnestic_disillusive != 0) 
      free(((char *)catamnestic_disillusive));
stonesoup_close_printf_context();
  }
}
