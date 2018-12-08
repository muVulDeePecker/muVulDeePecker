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
#include <stonesoup/stonesoup_trace.h> 
int spare_hokypoky = 0;
int stonesoup_global_variable;

struct corning_incelebrity 
{
  char *sirs_afterstretch;
  double formule_ppe;
  char *topotypic_disemic;
  char springiness_rolpens;
  int simson_cocomposer;
}
;
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
void cadetcy_taboparalysis(struct corning_incelebrity *musimon_atavic);

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
{
  void (*wisps_academies)(struct corning_incelebrity *) = cadetcy_taboparalysis;
  struct corning_incelebrity *retrogresses_reattribution = 0;
  struct corning_incelebrity significatory_sublevels = {0};
  struct corning_incelebrity nonce_ammiolite;
  char *colymbion_renunciatory;;
  if (__sync_bool_compare_and_swap(&spare_hokypoky,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp8HiJfd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      colymbion_renunciatory = getenv("BEFRIENDER_URANOPHOBIA");
      if (colymbion_renunciatory != 0) {;
        nonce_ammiolite . sirs_afterstretch = ((char *)colymbion_renunciatory);
        retrogresses_reattribution = &nonce_ammiolite;
        wisps_academies(retrogresses_reattribution);
      }
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

void cadetcy_taboparalysis(struct corning_incelebrity *musimon_atavic)
{
  char *stonesoup_skip_malloc_buffer = 0;
  char *discordantness_lumine = 0;
  ++stonesoup_global_variable;;
  discordantness_lumine = ((char *)( *musimon_atavic) . sirs_afterstretch);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "G", "NULL Pointer Dereference");
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT */
      if (strlen(discordantness_lumine) < 63) {
        stonesoup_skip_malloc_buffer = malloc(strlen(discordantness_lumine + 1));
      }
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
      tracepoint(stonesoup_trace, variable_address, "stonesoup_skip_malloc_buffer", stonesoup_skip_malloc_buffer, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference: Unchecked strcpy) */
      strcpy(stonesoup_skip_malloc_buffer,discordantness_lumine);
      stonesoup_printf("Buffer is %s\n",stonesoup_skip_malloc_buffer);
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      if (stonesoup_skip_malloc_buffer != 0) {
        free(stonesoup_skip_malloc_buffer);
      }
      tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
