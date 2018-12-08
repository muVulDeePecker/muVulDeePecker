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
int cestoi_kumari = 0;

union sits_appointer 
{
  char *cavaedium_befoulment;
  double hoven_unappetizing;
  char *subking_trochleate;
  char noughty_crypturidae;
  int blowse_chrysidid;
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
short stonesoup_get_int_value(char *ss_tainted_buff)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpVqs5mq_ss_testcase/src-rose/libavdevice/avdevice.c", "stonesoup_get_int_value");
  short to_short = 0;
  int tainted_int = 0;
  tainted_int = atoi(ss_tainted_buff);
  if (tainted_int != 0) {
    if (tainted_int > 30000)
      tainted_int = 30000;
    if (tainted_int < -30000)
      tainted_int = -30000;
    to_short = ((short )tainted_int);
  }
  return to_short;
}

unsigned int avdevice_version()
{
    unsigned int stonesoup_to_unsign = 0;
    char *stonesoup_buff = 0;
    FILE *stonesoup_file = 0;
    int stonesoup_counter = 0;
    int stonesoup_bytes_read = 0;
  char *piperide_truantship = 0;
  union sits_appointer freeloads_perling;
  char *kieselgur_phillis;;
  if (__sync_bool_compare_and_swap(&cestoi_kumari,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpVqs5mq_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      stonesoup_setup_printf_context();
      kieselgur_phillis = getenv("INFIXATION_SIBYLLIC");
      if (kieselgur_phillis != 0) {;
        freeloads_perling . cavaedium_befoulment = kieselgur_phillis;
        piperide_truantship = ((char *)freeloads_perling . cavaedium_befoulment);
    tracepoint(stonesoup_trace, weakness_start, "CWE194", "A", "Unexpected Sign Extension");
    stonesoup_buff = ((char *)(malloc(30000 * sizeof(char ))));
    if (stonesoup_buff == 0) {
        stonesoup_printf("Error: Failed to allocate memory\n");
        exit(1);
    }
    memset(stonesoup_buff, 0, 30000);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Unexpected Sign Extension) */
    stonesoup_to_unsign = stonesoup_get_int_value(piperide_truantship);
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", piperide_truantship, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_unsigned_integral, "stonesoup_to_unsign", stonesoup_to_unsign, &stonesoup_to_unsign, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    stonesoup_file = fopen("/opt/stonesoup/workspace/testData/myfile.txt","r");
    if (stonesoup_file != 0) {
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        while (((unsigned int )stonesoup_counter) < stonesoup_to_unsign) {
            /* STONESOUP: TRIGGER-POINT (Unexpected Sign Extension) */
            stonesoup_bytes_read = fread(&stonesoup_buff[stonesoup_counter],
                sizeof(char), 1000, stonesoup_file);
            if (stonesoup_bytes_read == 0) {
                break;
            }
            stonesoup_counter += stonesoup_bytes_read;
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        fclose(stonesoup_file);
        stonesoup_buff[stonesoup_to_unsign] = '\0';
        stonesoup_printf("buff is %d long, and has contents: %s \n",strlen(stonesoup_buff), stonesoup_buff);
    } else {
        stonesoup_printf("Cannot open file %s\n", "/opt/stonesoup/workspace/testData/myfile.txt");
    }
    if (stonesoup_buff != 0) {
        free(stonesoup_buff);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
      }
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
