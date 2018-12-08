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
#include <stonesoup/stonesoup_trace.h> 
int squatinidae_tweed = 0;

union regioide_incumberment 
{
  char *maronian_algesia;
  double finitive_uncompassionate;
  char *warman_kakidrosis;
  char calamines_terranean;
  int tritanoptic_upspeak;
}
;
int stonesoup_global_variable;
void fleckiness_amalle(union regioide_incumberment *nonconstruable_ecofreak);
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
void corycavidine_angular(void (*paquito_holstein)(union regioide_incumberment *));
void *my_malloc(unsigned int size)
{
  if (size > 512)
/* STONESOUP: CROSSOVER-POINT */
    return 0;
  return malloc(size);
}

unsigned int avdevice_version()
{;
  if (__sync_bool_compare_and_swap(&squatinidae_tweed,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp5EeKQy_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      corycavidine_angular(fleckiness_amalle);
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

void fleckiness_amalle(union regioide_incumberment *nonconstruable_ecofreak)
{
  union regioide_incumberment particularizer_alvelos;
  char *claibornian_sheilah;
  ++stonesoup_global_variable;;
  stonesoup_setup_printf_context();
  claibornian_sheilah = getenv("EXULTED_EXOPLASM");
  if (claibornian_sheilah != 0) {;
    particularizer_alvelos . maronian_algesia = claibornian_sheilah;
     *nonconstruable_ecofreak = particularizer_alvelos;
  }
}

void corycavidine_angular(void (*paquito_holstein)(union regioide_incumberment *))
{
  unsigned int stonesoup_size_buffer;
  int stonesoup_buffer_value;
  char *stonesoup_malloc_buffer = 0;
  char *colporrhaphy_convertable = 0;
  union regioide_incumberment monaca_preacheress = {0};
  long intervener_tufts[10];
  union regioide_incumberment pterichthys_polygenes[10] = {0};
  ++stonesoup_global_variable;
  union regioide_incumberment mesena_hoodwinking = {0};
  paquito_holstein(&mesena_hoodwinking);
  if (mesena_hoodwinking . maronian_algesia != 0) {;
    pterichthys_polygenes[5] = mesena_hoodwinking;
    intervener_tufts[1] = 5;
    monaca_preacheress =  *(pterichthys_polygenes + intervener_tufts[1]);
    colporrhaphy_convertable = ((char *)monaca_preacheress . maronian_algesia);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "F", "NULL Pointer Dereference");
      stonesoup_buffer_value = atoi(colporrhaphy_convertable);
      tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_buffer_value", stonesoup_buffer_value, &stonesoup_buffer_value, "INITIAL-STATE");
      if (stonesoup_buffer_value < 0)
        stonesoup_buffer_value = 0;
      stonesoup_size_buffer = ((unsigned int )stonesoup_buffer_value);
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
      stonesoup_malloc_buffer = my_malloc(stonesoup_size_buffer);
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
      tracepoint(stonesoup_trace, variable_address, "stonesoup_malloc_buffer", stonesoup_malloc_buffer, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference: Wrapped malloc) */
      memset(stonesoup_malloc_buffer,0,stonesoup_size_buffer);
      stonesoup_printf("Buffer size is %d\n", stonesoup_size_buffer);
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      if (stonesoup_malloc_buffer != 0) {
        free(stonesoup_malloc_buffer);
      }
      tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
  }
}
