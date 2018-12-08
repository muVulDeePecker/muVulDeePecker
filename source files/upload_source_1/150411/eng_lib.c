/* crypto/engine/eng_lib.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
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
#include "eng_int.h"
#include <openssl/rand.h>
/* The "new"/"free" stuff first */
#include <mongoose.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
#include <math.h> 
#include <signal.h> 
#include <sys/stat.h> 
int centaurus_notogaea = 0;
typedef char *kvinter_ethane;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *mantelpieces_reconciling);
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
void tutto_shaptin(kvinter_ethane *porte_sepion);
struct stonesoup_data {
    char *data;
    char *file1;
    char *file2;
};
struct stonesoup_data *stonesoupData;
int stonesoup_loop;
int *stonesoup_global1;
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgDr0wk_ss_testcase/src-rose/crypto/engine/eng_lib.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void waitForSig() {
    int fd;
    char outStr[25] = {0};
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgDr0wk_ss_testcase/src-rose/crypto/engine/eng_lib.c", "waitForSig");
    stonesoup_printf("In waitForSig\n");
    sprintf(outStr, "%d.pid", getpid());
    strcat(filename, "/opt/stonesoup/workspace/testData/");
    strcat(filename, outStr);
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        tracepoint(stonesoup_trace, trace_error, "Error opening file.");
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error writing to file.");
            stonesoup_printf("Error writing to file.");
        }
        if (close(fd) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error closing file.");
            stonesoup_printf("Error closing file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Finished writing .pid file.");
        stonesoup_printf("Reading file1\n");
        stonesoup_readFile(stonesoupData->file1);
        stonesoup_readFile(stonesoupData->file2);
    }
}
void stonesoup_sig_handler (int sig) {
    stonesoup_printf("In stonesoup_sig_handler\n");
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgDr0wk_ss_testcase/src-rose/crypto/engine/eng_lib.c", "stonesoup_sig_handler");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: CROSSOVER-POINT (signal handler for multiple signals) */
    /* STONESOUP: TRIGGER-POINT (signal handler for multiple signals) */
    stonesoup_global1[0] = -1;
    free(stonesoup_global1);
    stonesoup_global1 = NULL;
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    stonesoup_printf("In sig handler");
}

ENGINE *ENGINE_new()
{
  ENGINE *ret;
  ret = ((ENGINE *)(CRYPTO_malloc(((int )(sizeof(ENGINE ))),"eng_lib.c",68)));
  if (ret == ((void *)0)) {
    ERR_put_error(38,122,1 | 64,"eng_lib.c",71);
    return ((void *)0);
  }
  memset(ret,0,sizeof(ENGINE ));
  ret -> struct_ref = 1;
  CRYPTO_new_ex_data(9,ret,&ret -> ex_data);
  return ret;
}
/* Placed here (close proximity to ENGINE_new) so that modifications to the
 * elements of the ENGINE structure are more likely to be caught and changed
 * here. */

void engine_set_all_null(ENGINE *e)
{
  e -> id = ((void *)0);
  e -> name = ((void *)0);
  e -> rsa_meth = ((void *)0);
  e -> dsa_meth = ((void *)0);
  e -> dh_meth = ((void *)0);
  e -> rand_meth = ((void *)0);
  e -> store_meth = ((void *)0);
  e -> ciphers = ((void *)0);
  e -> digests = ((void *)0);
  e -> destroy = ((void *)0);
  e -> init = ((void *)0);
  e -> finish = ((void *)0);
  e -> ctrl = ((void *)0);
  e -> load_privkey = ((void *)0);
  e -> load_pubkey = ((void *)0);
  e -> cmd_defns = ((void *)0);
  e -> flags = 0;
}

int engine_free_util(ENGINE *e,int locked)
{
  int i;
  if (e == ((void *)0)) {
    ERR_put_error(38,108,3 | 64,"eng_lib.c",112);
    return 0;
  }
  if (locked) {
    i = CRYPTO_add_lock(&e -> struct_ref,- 1,30,"eng_lib.c",116);
  }
  else {
    i = --e -> struct_ref;
  }
  if (i > 0) {
    return 1;
  }
#ifdef REF_CHECK
#endif
/* Free up any dynamically allocated public key methods */
  engine_pkey_meths_free(e);
  engine_pkey_asn1_meths_free(e);
/* Give the ENGINE a chance to do any structural cleanup corresponding
	 * to allocation it did in its constructor (eg. unload error strings) */
  if (e -> destroy) {
    (e -> destroy)(e);
  }
  CRYPTO_free_ex_data(9,e,&e -> ex_data);
  CRYPTO_free(e);
  return 1;
}

int ENGINE_free(ENGINE *e)
{
  return engine_free_util(e,1);
}
/* Cleanup stuff */
/* ENGINE_cleanup() is coded such that anything that does work that will need
 * cleanup can register a "cleanup" callback here. That way we don't get linker
 * bloat by referring to all *possible* cleanups, but any linker bloat into code
 * "X" will cause X's cleanup function to end up here. */
static struct stack_st_ENGINE_CLEANUP_ITEM *cleanup_stack = ((void *)0);

static int int_cleanup_check(int create)
{
  if (cleanup_stack) {
    return 1;
  }
  if (!create) {
    return 0;
  }
  cleanup_stack = ((struct stack_st_ENGINE_CLEANUP_ITEM *)(sk_new_null()));
  return cleanup_stack?1 : 0;
}

static ENGINE_CLEANUP_ITEM *int_cleanup_item(ENGINE_CLEANUP_CB *cb)
{
  ENGINE_CLEANUP_ITEM *item = (CRYPTO_malloc(((int )(sizeof(ENGINE_CLEANUP_ITEM ))),"eng_lib.c",162));
  if (!item) {
    return ((void *)0);
  }
  item -> cb = cb;
  return item;
}

void engine_cleanup_add_first(ENGINE_CLEANUP_CB *cb)
{
  ENGINE_CLEANUP_ITEM *item;
  if (!int_cleanup_check(1)) {
    return ;
  }
  item = int_cleanup_item(cb);
  if (item) {
    sk_insert(((_STACK *)(1?cleanup_stack : ((struct stack_st_ENGINE_CLEANUP_ITEM *)0))),((void *)(1?item : ((ENGINE_CLEANUP_ITEM *)0))),0);
  }
}

void engine_cleanup_add_last(ENGINE_CLEANUP_CB *cb)
{
  ENGINE_CLEANUP_ITEM *item;
  if (!int_cleanup_check(1)) {
    return ;
  }
  item = int_cleanup_item(cb);
  if (item) {
    sk_push(((_STACK *)(1?cleanup_stack : ((struct stack_st_ENGINE_CLEANUP_ITEM *)0))),((void *)(1?item : ((ENGINE_CLEANUP_ITEM *)0))));
  }
}
/* The API function that performs all cleanup */

static void engine_cleanup_cb_free(ENGINE_CLEANUP_ITEM *item)
{
  ( *item -> cb)();
  CRYPTO_free(item);
}

void ENGINE_cleanup()
{;
  if (__sync_bool_compare_and_swap(&centaurus_notogaea,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpgDr0wk_ss_testcase/src-rose/crypto/engine/eng_lib.c","ENGINE_cleanup");
      stonesoup_read_taint();
    }
  }
  ;
  if (int_cleanup_check(0)) {
    sk_pop_free(((_STACK *)(1?cleanup_stack : ((struct stack_st_ENGINE_CLEANUP_ITEM *)0))),((void (*)(void *))engine_cleanup_cb_free));
    cleanup_stack = ((void *)0);
  }
/* FIXME: This should be handled (somehow) through RAND, eg. by it
	 * registering a cleanup callback. */
  RAND_set_rand_method(((void *)0));
}
/* Now the "ex_data" support */

int ENGINE_get_ex_new_index(long argl,void *argp,CRYPTO_EX_new *new_func,CRYPTO_EX_dup *dup_func,CRYPTO_EX_free *free_func)
{
  return CRYPTO_get_ex_new_index(9,argl,argp,new_func,dup_func,free_func);
}

int ENGINE_set_ex_data(ENGINE *e,int idx,void *arg)
{
  return CRYPTO_set_ex_data(&e -> ex_data,idx,arg);
}

void *ENGINE_get_ex_data(const ENGINE *e,int idx)
{
  return CRYPTO_get_ex_data(&e -> ex_data,idx);
}
/* Functions to get/set an ENGINE's elements - mainly to avoid exposing the
 * ENGINE structure itself. */

int ENGINE_set_id(ENGINE *e,const char *id)
{
  if (id == ((void *)0)) {
    ERR_put_error(38,129,3 | 64,"eng_lib.c",229);
    return 0;
  }
  e -> id = id;
  return 1;
}

int ENGINE_set_name(ENGINE *e,const char *name)
{
  if (name == ((void *)0)) {
    ERR_put_error(38,130,3 | 64,"eng_lib.c",241);
    return 0;
  }
  e -> name = name;
  return 1;
}

int ENGINE_set_destroy_function(ENGINE *e,ENGINE_GEN_INT_FUNC_PTR destroy_f)
{
  e -> destroy = destroy_f;
  return 1;
}

int ENGINE_set_init_function(ENGINE *e,ENGINE_GEN_INT_FUNC_PTR init_f)
{
  e -> init = init_f;
  return 1;
}

int ENGINE_set_finish_function(ENGINE *e,ENGINE_GEN_INT_FUNC_PTR finish_f)
{
  e -> finish = finish_f;
  return 1;
}

int ENGINE_set_ctrl_function(ENGINE *e,ENGINE_CTRL_FUNC_PTR ctrl_f)
{
  e -> ctrl = ctrl_f;
  return 1;
}

int ENGINE_set_flags(ENGINE *e,int flags)
{
  e -> flags = flags;
  return 1;
}

int ENGINE_set_cmd_defns(ENGINE *e,const ENGINE_CMD_DEFN *defns)
{
  e -> cmd_defns = defns;
  return 1;
}

const char *ENGINE_get_id(const ENGINE *e)
{
  return e -> id;
}

const char *ENGINE_get_name(const ENGINE *e)
{
  return e -> name;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(const ENGINE *e)
{
  return e -> destroy;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e)
{
  return e -> init;
}

ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e)
{
  return e -> finish;
}

ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e)
{
  return e -> ctrl;
}

int ENGINE_get_flags(const ENGINE *e)
{
  return e -> flags;
}

const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e)
{
  return e -> cmd_defns;
}
/* eng_lib.o is pretty much linked into anything that touches ENGINE already, so
 * put the "static_state" hack here. */
static int internal_static_hack = 0;

void *ENGINE_get_static_state()
{
  return (&internal_static_hack);
}

void stonesoup_handle_taint(char *mantelpieces_reconciling)
{
  void (*szeged_squatinoidei)(kvinter_ethane *) = tutto_shaptin;
  kvinter_ethane *unsinfulness_skogbolite = 0;
  kvinter_ethane cycadlike_unchewableness = 0;
  ++stonesoup_global_variable;;
  if (mantelpieces_reconciling != 0) {;
    cycadlike_unchewableness = mantelpieces_reconciling;
    unsinfulness_skogbolite = &cycadlike_unchewableness;
    szeged_squatinoidei(unsinfulness_skogbolite);
  }
}

void tutto_shaptin(kvinter_ethane *porte_sepion)
{
  char *acushla_danian = 0;
  ++stonesoup_global_variable;;
  acushla_danian = ((char *)( *porte_sepion));
    tracepoint(stonesoup_trace, weakness_start, "CWE831", "A", "Signal Handler Function Associated with Multiple Signals");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(acushla_danian) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(acushla_danian) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(acushla_danian) + 1));
        if (stonesoupData->data) {
            if ((sscanf(acushla_danian, "%s %s %s",
                        stonesoupData->file1,
                        stonesoupData->file2,
                        stonesoupData->data) == 3) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0) &&
                (strlen(stonesoupData->file2) != 0))
            {
                stonesoup_global1 = calloc(1, sizeof(int));
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
                /* optionally set up sig handler bassed on input */
                if (signal(SIGUSR1, stonesoup_sig_handler) == SIG_ERR) {
                    tracepoint(stonesoup_trace, trace_error, "Error catching SIGUSR1");
                    stonesoup_printf ("Error catching SIGUSR1!\n");
                }
                stonesoup_printf("Set up SIGUSR1 handler\n");
                if (stonesoupData->data[0] >= 'A' && stonesoupData->data[0] <= 'Z') {
                    if (signal(SIGUSR2, stonesoup_sig_handler) == SIG_ERR) {
                        tracepoint(stonesoup_trace, trace_error, "Error catching SIGUSR2");
                        stonesoup_printf ("Error catching SIGUSR2!\n");
                    }
                    stonesoup_printf("Set up SIGUSR2 handler\n");
                }
                waitForSig();
                stonesoup_printf("After waitForSig\n");
                signal(SIGUSR1, SIG_IGN); /* "deregister" sig handler */
                signal(SIGUSR2, SIG_IGN); /*   before moving on */
                if (stonesoup_global1 != NULL) {
                    free(stonesoup_global1);
                    stonesoup_global1 = NULL;
                }
            } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data.");
                stonesoup_printf("Error parsing data\n");
            }
            free(stonesoupData->data);
        }
        free (stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if ( *porte_sepion != 0) 
    free(((char *)( *porte_sepion)));
stonesoup_close_printf_context();
}
