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
#include <sys/stat.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
int interregnal_spirobranchia = 0;
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
char *evaluates_irremeably(char *ransomers_hortensia);
struct stonesoup_list {
    int data;
    struct stonesoup_list *previous;
    struct stonesoup_list *next;
};
struct stonesoup_queue {
    pthread_mutex_t lock;
    pthread_cond_t is_empty;
    pthread_cond_t is_full;
    int size;
    int capacity;
    struct stonesoup_list *head;
    struct stonesoup_list *tail;
};
struct stonesoup_data {
    int qsize;
    int data;
    char* file1;
    char* file2;
};
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpvjmKyL_ss_testcase/src-rose/crypto/engine/eng_lib.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpvjmKyL_ss_testcase/src-rose/crypto/engine/eng_lib.c", "Finished reading sync file.");
}
int enqueue(struct stonesoup_queue *ssQ, int data) {
    int rtnval = 0;
    if (ssQ != NULL) {
        struct stonesoup_list *elem = malloc(sizeof(struct stonesoup_list));
        pthread_mutex_lock(&(ssQ->lock));
        while (ssQ->size >= ssQ->capacity) {
            pthread_cond_wait(&(ssQ->is_full), &(ssQ->lock));
        }
        elem->next = NULL;
        elem->previous = ssQ->tail;
        elem->data = data;
        if (ssQ->tail != NULL) {
            ssQ->tail->next = elem;
        }
        ssQ->tail = elem;
        ssQ->size++;
        if (ssQ->head == NULL) {
            ssQ->head = elem;
        }
        pthread_mutex_unlock(&(ssQ->lock));
        pthread_cond_broadcast(&(ssQ->is_empty));
        }
    else {
        rtnval = -1;
    }
    return rtnval;
}
int dequeue(struct stonesoup_queue *ssQ) {
    int val = -1;
    if (ssQ != NULL) {
        struct stonesoup_list *elem;
        pthread_mutex_lock(&(ssQ->lock));
        while (ssQ->size <= 0) {
            pthread_cond_wait(&(ssQ->is_empty), &(ssQ->lock));
        }
        elem = ssQ->head;
        ssQ->head = elem->next;
        if(ssQ->head != NULL) {
            ssQ->head->previous = NULL;
        }
        else {
            ssQ->tail = NULL;
        }
        val = elem->data;
        ssQ->size--;
        free(elem);
        pthread_mutex_unlock(&(ssQ->lock));
        pthread_cond_broadcast(&(ssQ->is_full));
    }
    return val;
}
struct stonesoup_queue *get_instance (char* file2) {
    static struct stonesoup_queue *ssQ = NULL;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpvjmKyL_ss_testcase/src-rose/crypto/engine/eng_lib.c", "get_instance");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    /* STONESOUP: CROSSOVER-POINT (singletonpatternwithoutsync) */
    if (ssQ == NULL) {
        if (file2 != NULL) {
            stonesoup_readFile(file2);
        }
        ssQ = (struct stonesoup_queue *)calloc(1, sizeof(struct stonesoup_queue));
        pthread_mutex_init(&(ssQ->lock), NULL);
        pthread_cond_init(&(ssQ->is_empty), NULL);
        pthread_cond_init(&(ssQ->is_full), NULL);
        ssQ->size = 0;
        ssQ->capacity = 30;
        ssQ->head = NULL;
        ssQ->tail = NULL;
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_address, "ssQ", ssQ, "CROSSOVER-STATE");
    return ssQ;
}
void *stonesoup_print_data (void *data) {
    struct stonesoup_data *ssD = (struct stonesoup_data *)data;
    struct stonesoup_queue *ssQ = get_instance(ssD->file2);
    int i;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpvjmKyL_ss_testcase/src-rose/crypto/engine/eng_lib.c", "stonesoup_print_data");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (singletonpatternwithoutsync) */
    while ((i = dequeue(ssQ)) != -1) {
        stonesoup_printf("Data: %d\n", i);
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    return NULL;
}
void *stonesoup_calc_data (void *data) {
    struct stonesoup_data *ssD = (struct stonesoup_data *)data;
    struct stonesoup_queue *ssQ;
    int *qsort_arr;
    int i;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpvjmKyL_ss_testcase/src-rose/crypto/engine/eng_lib.c", "stonesoup_calc_data");
    qsort_arr = malloc(sizeof(int)*ssD->qsize);
        if (qsort_arr != NULL) {
            for (i = 0; i < ssD->qsize; i++) {
                qsort_arr[i] = ssD->qsize - i;
            }
            qsort(qsort_arr, ssD->qsize, sizeof(int), &stonesoup_comp);
            free (qsort_arr);
            qsort_arr = NULL;
        }
    stonesoup_readFile(ssD->file1);
    ssQ = get_instance(NULL);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT2: BEFORE");
    for (i = 0; i < ssD->data; i++) {
        /* STONESOUP2: TRIGGER-POINT (singletonpatternwithoutsync) */
        if (enqueue(ssQ, i) == -1) {
            break;
        }
    }
    enqueue(ssQ, -1);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT2: AFTER");
    return NULL;
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
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data* stonesoupData;
  char *hexamethylene_offendedly = 0;
  char *recharger_pdn = 0;
  int lagting_laurvikite = 91;
  char *hectoliter_titers;;
  if (__sync_bool_compare_and_swap(&interregnal_spirobranchia,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpvjmKyL_ss_testcase/src-rose/crypto/engine/eng_lib.c","ENGINE_cleanup");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&hectoliter_titers,"2708",lagting_laurvikite);
      if (hectoliter_titers != 0) {;
        recharger_pdn = evaluates_irremeably(hectoliter_titers);
        hexamethylene_offendedly = ((char *)recharger_pdn);
    tracepoint(stonesoup_trace, weakness_start, "CWE543", "A", "Use of a Singleton Pattern Without Synchronization in a Multithreaded Context");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(hexamethylene_offendedly) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(hexamethylene_offendedly) + 1));
        if ((sscanf(hexamethylene_offendedly, "%d %s %s %d",
                  &(stonesoupData->qsize),
                    stonesoupData->file1,
                    stonesoupData->file2,
                  &(stonesoupData->data)) == 4) &&
                    stonesoupData->qsize >= 0 &&
                    stonesoupData->data >= 0 &&
            (strlen(stonesoupData->file1) != 0) &&
            (strlen(stonesoupData->file2) != 0))
        {
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->data", stonesoupData->data, &(stonesoupData->data), "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
            tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
            if (pthread_create(&stonesoup_t0, NULL, stonesoup_calc_data, stonesoupData) != 0) {
                stonesoup_printf("Thread 0 failed to spawn.");
            }
            if (pthread_create(&stonesoup_t1, NULL, stonesoup_print_data, stonesoupData) != 0) {
                stonesoup_printf("Thread 1 failed to spawn.");
            }
            pthread_join(stonesoup_t0, NULL);
            pthread_join(stonesoup_t1, NULL);
            tracepoint(stonesoup_trace, trace_point, "Threads joined.");
        } else {
            tracepoint(stonesoup_trace, trace_error, "Error parsng data.");
            stonesoup_printf("Error parsing data\n");
        }
        free(stonesoupData->file1);
        free(stonesoupData->file2);
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
        if (recharger_pdn != 0) 
          free(((char *)recharger_pdn));
stonesoup_close_printf_context();
      }
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

char *evaluates_irremeably(char *ransomers_hortensia)
{
  ++stonesoup_global_variable;
  return ransomers_hortensia;
}
