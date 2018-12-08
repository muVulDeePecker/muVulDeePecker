/*
 * svn_mutex.c: routines for mutual exclusion.
 *
 * ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */
#include "svn_private_config.h"
#include "private/svn_mutex.h"
#include <sys/stat.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
#include <semaphore.h> 
int garrick_unfanged = 0;
int stonesoup_global_variable;
void odalisks_retrocervical(char **maureen_hieing);
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
void pitressin_ergotin(void (*vidry_swizz)(char **));
sem_t stonesoup_sem;
pthread_t stonesoup_t0, stonesoup_t1;
char *stonesoup_global_str;
int stonesoup_isspace(char c) {
    return (c == ' ' || c == '\t' || c == '\n');
}
void *replaceSpace () {
    int stonesoup_i = 0;
    stonesoup_printf("Replacing spaces\n");
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpxm4H3b_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "replaceSpace");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (multiple locks) */
    sem_wait(&stonesoup_sem); /* multiple locks - deadlock */
    sem_wait(&stonesoup_sem);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    while(stonesoup_global_str[stonesoup_i] != '\0') {
        if (stonesoup_isspace(stonesoup_global_str[stonesoup_i]) != 0) {
            stonesoup_global_str[stonesoup_i] = '_';
        }
        stonesoup_i++;
    }
    sem_post(&stonesoup_sem);
    return NULL;
}
void *toCap () {
    int stonesoup_i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpxm4H3b_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "toCap");
    tracepoint(stonesoup_trace, trace_point, "Before sem_wait in toCap");
    stonesoup_printf("Capitalizing input\n");
    sem_wait(&stonesoup_sem);
    tracepoint(stonesoup_trace, trace_point, "After sem_wait in toCap");
    while(stonesoup_global_str[stonesoup_i] != '\0') {
        if (stonesoup_global_str[stonesoup_i] > 'a' && stonesoup_global_str[stonesoup_i] < 'z') {
            stonesoup_global_str[stonesoup_i] -= 'a' - 'A';
        }
        stonesoup_i++;
    }
    sem_post(&stonesoup_sem);
    return NULL;
}

svn_error_t *svn_mutex__init(svn_mutex__t **mutex_p,svn_boolean_t mutex_required,apr_pool_t *result_pool)
{
/* always initialize the mutex pointer, even though it is not
     strictly necessary if APR_HAS_THREADS has not been set */
   *mutex_p = ((void *)0);
#if APR_HAS_THREADS
  if (mutex_required) {
    apr_thread_mutex_t *apr_mutex;
    apr_status_t status = apr_thread_mutex_create(&apr_mutex,0,result_pool);
    if (status) {
      return svn_error_wrap_apr(status,(dgettext("subversion","Can't create mutex")));
    }
     *mutex_p = apr_mutex;
  }
#endif
  return 0;
}

svn_error_t *svn_mutex__lock(svn_mutex__t *mutex)
{
#if APR_HAS_THREADS
  if (mutex) {
    apr_status_t status = apr_thread_mutex_lock(mutex);
    if (status) {
      return svn_error_wrap_apr(status,(dgettext("subversion","Can't lock mutex")));
    }
  }
#endif
  return 0;
}

svn_error_t *svn_mutex__unlock(svn_mutex__t *mutex,svn_error_t *err)
{;
  if (__sync_bool_compare_and_swap(&garrick_unfanged,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpxm4H3b_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      pitressin_ergotin(odalisks_retrocervical);
    }
  }
  ;
#if APR_HAS_THREADS
  if (mutex) {
    apr_status_t status = apr_thread_mutex_unlock(mutex);
    if (status && !err) {
      return svn_error_wrap_apr(status,(dgettext("subversion","Can't unlock mutex")));
    }
  }
#endif
  return err;
}

void odalisks_retrocervical(char **maureen_hieing)
{
  int bunnymouth_sublavius = 24;
  char *sierraville_kimberlite;
  ++stonesoup_global_variable;;
  stonesoup_setup_printf_context();
  stonesoup_read_taint(&sierraville_kimberlite,"9456",bunnymouth_sublavius);
  if (sierraville_kimberlite != 0) {;
     *maureen_hieing = sierraville_kimberlite;
  }
}

void pitressin_ergotin(void (*vidry_swizz)(char **))
{
    int stonesoup_hasSpaces = 0;
    int stonesoup_i = 0;
  char *exchangeably_immonastered = 0;
  char *congruence_raphaelle = 0;
  long kossuth_equalize[10];
  char *unsinningness_loutishly[10] = {0};
  ++stonesoup_global_variable;
  char *epidermolysis_haematoid = 0;
  vidry_swizz(&epidermolysis_haematoid);
  if (epidermolysis_haematoid != 0) {;
    unsinningness_loutishly[5] = epidermolysis_haematoid;
    kossuth_equalize[1] = 5;
    congruence_raphaelle =  *(unsinningness_loutishly + kossuth_equalize[1]);
    exchangeably_immonastered = ((char *)congruence_raphaelle);
    tracepoint(stonesoup_trace, weakness_start, "CWE764", "A", "Multiple Locks of a Critical Resource");
    sem_init(&stonesoup_sem, 0, 1);
    while(exchangeably_immonastered[stonesoup_i] != '\0') { /* if the input contains spaces */
        if (stonesoup_isspace(exchangeably_immonastered[stonesoup_i++]) != 0) { /* we will call the deadlocking function */
            stonesoup_hasSpaces = 1;
        }
    }
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", exchangeably_immonastered, "INITIAL-STATE");
    stonesoup_global_str = malloc(sizeof(char) * strlen(exchangeably_immonastered) + 1);
    strcpy(stonesoup_global_str, exchangeably_immonastered);
    if (stonesoup_hasSpaces == 1) {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        /* STONESOUP: CROSSOVER-POINT (multiple locks) */
        if (pthread_create(&stonesoup_t0, NULL, replaceSpace, NULL) != 0) {
            stonesoup_printf("Thread 0 failed to spawn.");
        }
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    }
    if (pthread_create(&stonesoup_t1, NULL, toCap, NULL) != 0) {
        stonesoup_printf("Thread 1 failed to spawn.");
    }
    if (stonesoup_hasSpaces == 1) {
        pthread_join(stonesoup_t0, NULL);
    }
    pthread_join(stonesoup_t1, NULL);
    tracepoint(stonesoup_trace, weakness_end);
;
    if (congruence_raphaelle != 0) 
      free(((char *)congruence_raphaelle));
stonesoup_close_printf_context();
  }
}
