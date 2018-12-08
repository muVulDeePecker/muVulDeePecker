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
#include <mongoose.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <ctype.h> 
#include <sys/stat.h> 
int bibio_denasalize = 0;

struct unwrite_semiferal 
{
  char *fuselage_apoplectic;
  double headhunters_shufflers;
  char *sourcefulness_kendo;
  char sardius_anathemata;
  int murdrum_countermine;
}
;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *gadsman_fordham);
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
void subchorioid_appointers(struct unwrite_semiferal *presupplicating_timidest);
void bullshitted_zonate(struct unwrite_semiferal *coloraturas_underfarmer);
void verdancy_occidental(struct unwrite_semiferal *anisogamic_wiedersehen);
void fluorocarbon_bello(struct unwrite_semiferal *eldrida_lenitives);
void humorsomeness_liasing(struct unwrite_semiferal *catagenesis_mantelet);
void granddaughterly_oscitance(struct unwrite_semiferal *dermatoplasm_redux);
void entheos_stoot(struct unwrite_semiferal *unrippling_monobromized);
void unpondered_hamantashen(struct unwrite_semiferal *unseel_wheer);
void unpurchased_phonometric(struct unwrite_semiferal *masticate_scamler);
void redbeard_collabent(struct unwrite_semiferal *outadd_light);
void urlDecode(char *src, char *dst) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
                ((a = src[1]) && (b = src[2])) &&
                (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a')
                a -= 'a'-'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a'-'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}
int isValid(char *src) {
    int i = 0;
    while (src[i] != '\0') {
        if(src[i] == ';') {
            if (i == 0 || src[i-1] != '\\') {
                return 0;
            }
        }
        else if(src[i] == '|') {
            if (i == 0 || src[i-1] != '\\') {
                return 0;
            }
        }
        else if(src[i] == '&') {
            if (i == 0 || src[i-1] != '\\') {
                return 0;
            }
        }
        i++;
    }
    return 1;
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
  if (__sync_bool_compare_and_swap(&bibio_denasalize,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpYmFLv2_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_read_taint();
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

void stonesoup_handle_taint(char *gadsman_fordham)
{
  int doxological_disshadow;
  struct unwrite_semiferal *vidal_fieldball = {0};
  struct unwrite_semiferal *paterfamilias_burrock = {0};
  struct unwrite_semiferal koeri_climates;
  ++stonesoup_global_variable;;
  if (gadsman_fordham != 0) {;
    koeri_climates . fuselage_apoplectic = ((char *)gadsman_fordham);
    doxological_disshadow = 1;
    vidal_fieldball = &koeri_climates;
    paterfamilias_burrock = ((struct unwrite_semiferal *)(((unsigned long )vidal_fieldball) * doxological_disshadow * doxological_disshadow)) + 5;
    subchorioid_appointers(paterfamilias_burrock);
  }
}

void subchorioid_appointers(struct unwrite_semiferal *presupplicating_timidest)
{
  ++stonesoup_global_variable;;
  bullshitted_zonate(presupplicating_timidest);
}

void bullshitted_zonate(struct unwrite_semiferal *coloraturas_underfarmer)
{
  ++stonesoup_global_variable;;
  verdancy_occidental(coloraturas_underfarmer);
}

void verdancy_occidental(struct unwrite_semiferal *anisogamic_wiedersehen)
{
  ++stonesoup_global_variable;;
  fluorocarbon_bello(anisogamic_wiedersehen);
}

void fluorocarbon_bello(struct unwrite_semiferal *eldrida_lenitives)
{
  ++stonesoup_global_variable;;
  humorsomeness_liasing(eldrida_lenitives);
}

void humorsomeness_liasing(struct unwrite_semiferal *catagenesis_mantelet)
{
  ++stonesoup_global_variable;;
  granddaughterly_oscitance(catagenesis_mantelet);
}

void granddaughterly_oscitance(struct unwrite_semiferal *dermatoplasm_redux)
{
  ++stonesoup_global_variable;;
  entheos_stoot(dermatoplasm_redux);
}

void entheos_stoot(struct unwrite_semiferal *unrippling_monobromized)
{
  ++stonesoup_global_variable;;
  unpondered_hamantashen(unrippling_monobromized);
}

void unpondered_hamantashen(struct unwrite_semiferal *unseel_wheer)
{
  ++stonesoup_global_variable;;
  unpurchased_phonometric(unseel_wheer);
}

void unpurchased_phonometric(struct unwrite_semiferal *masticate_scamler)
{
  ++stonesoup_global_variable;;
  redbeard_collabent(masticate_scamler);
}

void redbeard_collabent(struct unwrite_semiferal *outadd_light)
{
    FILE *stonesoup_fpipe;
    char stonesoup_buffer[100];
    char *stonesoup_parsed_input;
    char stonesoup_command_buffer[1000];
    char *stonesoup_command_str = "nslookup ";
  char *boast_frostproofing = 0;
  ++stonesoup_global_variable;;
  boast_frostproofing = ((char *)( *(outadd_light - 5)) . fuselage_apoplectic);
    tracepoint(stonesoup_trace, weakness_start, "CWE078", "A", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')");
    if (strlen(boast_frostproofing) < 1000 - strlen(stonesoup_command_str)) {
        tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", boast_frostproofing, "INITIAL-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        /* STONESOUP: CROSSOVER-POINT (OS Command Injection) */
        if (isValid(boast_frostproofing) == 1) {
            stonesoup_parsed_input = malloc((strlen(boast_frostproofing)+1) * sizeof(char));
            urlDecode(boast_frostproofing, stonesoup_parsed_input);
            snprintf(stonesoup_command_buffer, 1000, "%s%s",stonesoup_command_str, stonesoup_parsed_input);
            tracepoint(stonesoup_trace, variable_buffer, "stonesoup_command_buffer", stonesoup_command_buffer, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
            /* STONESOUP: TRIGGER-POINT (OS Command Injection) */
            stonesoup_fpipe = popen(stonesoup_command_buffer,"r");
            if (stonesoup_fpipe != 0) {
                while(fgets(stonesoup_buffer,100,stonesoup_fpipe) != 0) {
                    stonesoup_printf(stonesoup_buffer);
                }
                pclose(stonesoup_fpipe);
            }
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (( *(outadd_light - 5)) . fuselage_apoplectic != 0) 
    free(((char *)( *(outadd_light - 5)) . fuselage_apoplectic));
stonesoup_close_printf_context();
}
