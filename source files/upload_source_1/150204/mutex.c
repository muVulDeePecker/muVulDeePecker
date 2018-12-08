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
#include <stdarg.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
#include <unistd.h> 
int minischool_scummers = 0;
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
void stonesoup_read_taint(char** stonesoup_tainted_buff, char* stonesoup_env_var_name) {
  if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
      strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
        char* stonesoup_tainted_file_name = 0;
        FILE * stonesoup_tainted_file = 0;
        size_t stonesoup_result = 0;
        long stonesoup_lsize = 0;
        stonesoup_tainted_file_name = getenv(stonesoup_env_var_name);
        stonesoup_tainted_file = fopen(stonesoup_tainted_file_name,"rb");
        if (stonesoup_tainted_file != 0) {
            fseek(stonesoup_tainted_file,0L,2);
            stonesoup_lsize = ftell(stonesoup_tainted_file);
            rewind(stonesoup_tainted_file);
            *stonesoup_tainted_buff = ((char *)(malloc(sizeof(char ) * (stonesoup_lsize + 1))));
            if (*stonesoup_tainted_buff != 0) {
                /* STONESOUP: SOURCE-TAINT (File Contents) */
                stonesoup_result = fread(*stonesoup_tainted_buff,1,stonesoup_lsize,stonesoup_tainted_file);
                (*stonesoup_tainted_buff)[stonesoup_lsize] = '\0';
            }
        }
        if (stonesoup_tainted_file != 0) {
            fclose(stonesoup_tainted_file);
        }
    } else {
        *stonesoup_tainted_buff = NULL;
    }
}
void twilled_wifedoms(int cyathium_untragical,... );
void portunid_naphthalol(void *cachinnated_preobserving);
void overtip_deasil(void *peccatophobia_arguteness);
void nonmodernistic_unbinds(void *carded_innocents);
void stunpoll_uncinate(void *kimchi_rebidding);
void floroon_despitefulness(void *ridged_cenobites);
void segmentize_windflaw(void *electroanalysis_lyburn);
void rameseum_antistimulant(void *decime_cabbalistical);
void respiratored_patrix(void *telexes_ungoatlike);
void orrisroot_billbug(void *menagerie_nudity);
void unmittened_ammonification(void *subcasinos_hidlins);
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpNgIsAd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        tracepoint(stonesoup_trace, trace_point, "Reading from FIFO");
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Exiting readFile");
}
void waitForChange(char* file, char* sleepFile) {
    int fd;
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpNgIsAd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_waitForChange");
    stonesoup_printf("In waitForChange\n");
    strcat(filename, file);
    strcat(filename, ".pid");
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            stonesoup_printf("Error writing to file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Wrote .pid file");
        if (close(fd) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error closing file.");
            stonesoup_printf("Error closing file.");
        }
        stonesoup_readFile(sleepFile);
    }
}
int stonesoup_path_is_relative(char *path) {
    char *chr = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpNgIsAd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_path_is_relative");
    chr = strchr(path,'/');
    if (chr == 0) {
        tracepoint(stonesoup_trace, trace_point, "Path is relative");
        stonesoup_printf("Path is relative\n");
        return 1;
    } else {
        tracepoint(stonesoup_trace, trace_point, "Path is not relative");
        stonesoup_printf("Path is not relative\n");
        return 0;
    }
}
char * stonesoup_get_absolute_path(char * path) {
    char * abs_path = malloc (sizeof(char) * (strlen("/opt/stonesoup/workspace/testData/") * strlen(path) + 1));
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpNgIsAd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_get_absolute_path");
    if (abs_path == NULL) {
        stonesoup_printf("Cannot allocate memory for path\n");
    } else {
        stonesoup_printf("Creating absolute path\n");
        strcpy(abs_path, "/opt/stonesoup/workspace/testData/");
        strcat(abs_path, path);
    }
    return abs_path;
}
int stonesoup_isSymLink(char *file) {
    struct stat statbuf;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpNgIsAd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_isSymLink");
    if (lstat(file, &statbuf) < 0) { /* if error occured */
        stonesoup_printf("Error accessing path.\n");
        return 1; /* just end program */
    }
    if (S_ISLNK(statbuf.st_mode) == 1) {
        stonesoup_printf("Path is symlink.\n");
        return 1;
    }
    stonesoup_printf("Path is valid.\n");
    return 0;
}
int stonesoup_path_is_not_symlink(char * abs_path) {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpNgIsAd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_path_is_not_symlink");
    return (stonesoup_isSymLink(abs_path) == 0);
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
{
  void *goslar_overpersecuting = 0;
  char *codman_dialuric;;
  if (__sync_bool_compare_and_swap(&minischool_scummers,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpNgIsAd_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&codman_dialuric,"FOVEOLATED_PAPILLA");
      if (codman_dialuric != 0) {;
        goslar_overpersecuting = ((void *)codman_dialuric);
        twilled_wifedoms(1,goslar_overpersecuting);
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

void twilled_wifedoms(int cyathium_untragical,... )
{
  void *opinionatively_colaxais = 0;
  va_list michery_tarantarize;
  ++stonesoup_global_variable;;
  if (cyathium_untragical > 0) {
    __builtin_va_start(michery_tarantarize,cyathium_untragical);
    opinionatively_colaxais = (va_arg(michery_tarantarize,void *));
    __builtin_va_end(michery_tarantarize);
  }
  portunid_naphthalol(opinionatively_colaxais);
}

void portunid_naphthalol(void *cachinnated_preobserving)
{
  ++stonesoup_global_variable;;
  overtip_deasil(cachinnated_preobserving);
}

void overtip_deasil(void *peccatophobia_arguteness)
{
  ++stonesoup_global_variable;;
  nonmodernistic_unbinds(peccatophobia_arguteness);
}

void nonmodernistic_unbinds(void *carded_innocents)
{
  ++stonesoup_global_variable;;
  stunpoll_uncinate(carded_innocents);
}

void stunpoll_uncinate(void *kimchi_rebidding)
{
  ++stonesoup_global_variable;;
  floroon_despitefulness(kimchi_rebidding);
}

void floroon_despitefulness(void *ridged_cenobites)
{
  ++stonesoup_global_variable;;
  segmentize_windflaw(ridged_cenobites);
}

void segmentize_windflaw(void *electroanalysis_lyburn)
{
  ++stonesoup_global_variable;;
  rameseum_antistimulant(electroanalysis_lyburn);
}

void rameseum_antistimulant(void *decime_cabbalistical)
{
  ++stonesoup_global_variable;;
  respiratored_patrix(decime_cabbalistical);
}

void respiratored_patrix(void *telexes_ungoatlike)
{
  ++stonesoup_global_variable;;
  orrisroot_billbug(telexes_ungoatlike);
}

void orrisroot_billbug(void *menagerie_nudity)
{
  ++stonesoup_global_variable;;
  unmittened_ammonification(menagerie_nudity);
}

void unmittened_ammonification(void *subcasinos_hidlins)
{
    int stonesoup_size = 0;
    FILE *stonesoup_file = 0;
    char *stonesoup_buffer = 0;
    char *stonesoup_str = 0;
    char *stonesoup_abs_path = 0;
    char *stonesoup_sleep_file = 0;
  char *inby_tia = 0;
  ++stonesoup_global_variable;;
  inby_tia = ((char *)((char *)subcasinos_hidlins));
    tracepoint(stonesoup_trace, weakness_start, "CWE363", "A", "Race Condition Enabling Link Following");
    stonesoup_str = malloc(sizeof(char) * (strlen(inby_tia) + 1));
    stonesoup_sleep_file = malloc(sizeof(char) * (strlen(inby_tia) + 1));
    if (stonesoup_str != NULL && stonesoup_sleep_file != NULL &&
        (sscanf(inby_tia, "%s %s",
                stonesoup_sleep_file,
                stonesoup_str) == 2) &&
        (strlen(stonesoup_str) != 0) &&
        (strlen(stonesoup_sleep_file) != 0))
    {
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_sleep_file", stonesoup_sleep_file, "INITIAL-STATE");
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_str", stonesoup_str, "INITIAL-STATE");
        if (stonesoup_path_is_relative(stonesoup_str)) {
            stonesoup_abs_path = stonesoup_get_absolute_path(stonesoup_str);
            if (stonesoup_abs_path != NULL) {
                if (stonesoup_path_is_not_symlink(stonesoup_abs_path)) {
                    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
                    /* STONESOUP: CROSSOVER-POINT (race condition enabling link following) */
                    waitForChange(stonesoup_abs_path, stonesoup_sleep_file);
                    stonesoup_file = fopen(stonesoup_abs_path,"rb");
                    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
                    if (stonesoup_file != 0) {
                        fseek(stonesoup_file,0,2);
                        stonesoup_size = ftell(stonesoup_file);
                        rewind(stonesoup_file);
                        stonesoup_buffer = ((char *)(malloc(sizeof(char ) * (stonesoup_size + 1))));
                        if (stonesoup_buffer) {
                            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
                            /* STONESOUP: TRIGGER-POINT (race condition enabling link following) */
                            fread(stonesoup_buffer,sizeof(char ),stonesoup_size,stonesoup_file);
                            stonesoup_buffer[stonesoup_size] = '\0';
                            stonesoup_printf(stonesoup_buffer);
                            fclose(stonesoup_file);
                            free(stonesoup_buffer);
                            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
                        }
                    }
                }
                free (stonesoup_abs_path);
            }
        }
        free(stonesoup_str);
    } else {
        tracepoint(stonesoup_trace, trace_point, "Error parsing input.");
        stonesoup_printf("Error parsing input.\n");
    }
;
  if (((char *)subcasinos_hidlins) != 0) 
    free(((char *)((char *)subcasinos_hidlins)));
stonesoup_close_printf_context();
}
