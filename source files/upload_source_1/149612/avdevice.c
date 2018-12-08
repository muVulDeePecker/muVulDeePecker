/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "libavutil/avassert.h"
#include "avdevice.h"
#include "config.h"
#include <sys/stat.h> 
#include <stdarg.h> 
#include <stonesoup/stonesoup_trace.h> 
int memoirist_pinchback = 0;

union exfoliated_conners 
{
  char *marplotry_unchurchlike;
  double chazy_tidife;
  char *knightsen_nehantic;
  char fravashi_shathmont;
  int resaw_mastiches;
}
;
int stonesoup_global_variable;
void brood_nonmonetary(union exfoliated_conners *asclepiadic_hogmollies);
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
void deters_unmanliness(void (*beaverpelt_tidily)(union exfoliated_conners *));
void irradiations_antemask(int platitudinously_diana,... );

unsigned int avdevice_version()
{;
  if (__sync_bool_compare_and_swap(&memoirist_pinchback,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpgewVKv_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      deters_unmanliness(brood_nonmonetary);
    }
  }
  ;
  do {
    if (!(103 >= 100)) {
      av_log(((void *)0),0,"Assertion %s failed at %s:%d\n","103 >= 100","avdevice.c",25);
      abort();
    }
  }while (0);
  return ('6' << 16 | 3 << 8 | 103);
}

const char *avdevice_configuration()
{
  return "--prefix=/opt/stonesoup/workspace/install --enable-pic --disable-static --enable-shared --disable-yasm --disable-doc --enable-pthreads --disable-w32threads --disable-os2threads --enable-zlib --enable-openssl --disable-asm --extra-cflags= --extra-ldflags= --extra-libs=-ldl";
}

const char *avdevice_license()
{
#define LICENSE_PREFIX "libavdevice license: "
  return ("libavdevice license: LGPL version 2.1 or later" + sizeof("libavdevice license: ") - 1);
}

void brood_nonmonetary(union exfoliated_conners *asclepiadic_hogmollies)
{
  union exfoliated_conners promotive_antanaclasis;
  char *alvira_commodation;
  ++stonesoup_global_variable;;
  stonesoup_setup_printf_context();
  alvira_commodation = getenv("ALAMANCE_STHENIAS");
  if (alvira_commodation != 0) {;
    promotive_antanaclasis . marplotry_unchurchlike = alvira_commodation;
     *asclepiadic_hogmollies = promotive_antanaclasis;
  }
}

void deters_unmanliness(void (*beaverpelt_tidily)(union exfoliated_conners *))
{
  ++stonesoup_global_variable;
  union exfoliated_conners unscavengered_presto = {0};
  beaverpelt_tidily(&unscavengered_presto);
  if (unscavengered_presto . marplotry_unchurchlike != 0) {;
    irradiations_antemask(1,unscavengered_presto);
  }
}

void irradiations_antemask(int platitudinously_diana,... )
{
  size_t stonesoup_j = 0;
  size_t stonesoup_i = 0;
  char *stonesoup_second_buff = 0;
  char *stonesoup_finder = "aba";
  int stonesoup_check = 0;
  char *purgation_maars = 0;
  union exfoliated_conners tashnakist_acetonation = {0};
  va_list falderol_melodist;
  ++stonesoup_global_variable;;
  if (platitudinously_diana > 0) {
    __builtin_va_start(falderol_melodist,platitudinously_diana);
    tashnakist_acetonation = (va_arg(falderol_melodist,union exfoliated_conners ));
    __builtin_va_end(falderol_melodist);
  }
  purgation_maars = ((char *)tashnakist_acetonation . marplotry_unchurchlike);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "B", "NULL Pointer Dereference");
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
      for (stonesoup_i = 0; ((int )stonesoup_i) <= ((int )(strlen(purgation_maars) - strlen(stonesoup_finder))); ++stonesoup_i) {
        for (stonesoup_j = 0; stonesoup_j < strlen(stonesoup_finder); ++stonesoup_j) {
          if (purgation_maars[stonesoup_i + stonesoup_j] != stonesoup_finder[stonesoup_j]) {
            stonesoup_check = 0;
            break;
          }
          stonesoup_check = 1;
        }
/* STONESOUP: CROSSOVER-POINT (Null Pointer Dereference) */
        if (stonesoup_check == 1 && stonesoup_j == strlen(stonesoup_finder)) {
          stonesoup_printf("Found aba string\n");
          stonesoup_second_buff = &purgation_maars[stonesoup_i];
          break;
        }
      }
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
      tracepoint(stonesoup_trace, variable_address, "stonesoup_second_buff", stonesoup_second_buff, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference) */
      stonesoup_printf("String length is %i\n", strlen(stonesoup_second_buff));
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
