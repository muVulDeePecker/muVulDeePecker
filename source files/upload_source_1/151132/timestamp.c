/* timestamp.c
 * Routines for timestamp type setting.
 *
 * $Id: timestamp.c 40518 2012-01-15 21:59:11Z jmayer $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include "timestamp.h"
/* Init with an invalid value, so that "recent" in ui/gtk/menu.c can detect this
 * and distinguish it from a command line value */
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/stat.h> 
#include <stdarg.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <sys/types.h> 
#include <stonesoup/stonesoup_trace.h> 
static ts_type timestamp_type = TS_NOT_SET;
static int timestamp_precision = TS_PREC_AUTO_USEC;
static ts_seconds_type timestamp_seconds_type = TS_SECONDS_NOT_SET;
int slacker_zima = 0;
int stonesoup_global_variable;
typedef char *tzetse_nonpyogenic;
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
void jiggish_metoxenous(const tzetse_nonpyogenic shuln_jacobina);
void quisquilious_idiorrhythmy(int underplant_rotatoplane,tzetse_nonpyogenic emmenthal_unawakenedness);
struct stonesoup_struct {
    void (*stonesoup_function_ptr_1)();
    unsigned int stonesoup_input_num;
    void (*stonesoup_function_ptr_2)();
};
void stonesoup_function() {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpcwqaee_ss_testcase/src-rose/epan/timestamp.c", "stonesoup_function");
}

ts_type timestamp_get_type()
{
  return timestamp_type;
}

void timestamp_set_type(ts_type ts_t)
{
  timestamp_type = ts_t;
}

int timestamp_get_precision()
{
  tzetse_nonpyogenic tullibee_infixed = 0;
  int glancer_prosopantritis = 7;
  char *gozell_blunt;;
  if (__sync_bool_compare_and_swap(&slacker_zima,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpcwqaee_ss_testcase/src-rose/epan/timestamp.c","timestamp_get_precision");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&gozell_blunt,"1380",glancer_prosopantritis);
      if (gozell_blunt != 0) {;
        tullibee_infixed = gozell_blunt;
        jiggish_metoxenous(tullibee_infixed);
      }
    }
  }
  ;
  return timestamp_precision;
}

void timestamp_set_precision(int tsp)
{
  timestamp_precision = tsp;
}

ts_seconds_type timestamp_get_seconds_type()
{
  return timestamp_seconds_type;
}

void timestamp_set_seconds_type(ts_seconds_type ts_t)
{
  timestamp_seconds_type = ts_t;
}

void jiggish_metoxenous(const tzetse_nonpyogenic shuln_jacobina)
{
  int eshin_lipolyses = 7;
  ++stonesoup_global_variable;;
  quisquilious_idiorrhythmy(eshin_lipolyses,shuln_jacobina);
}

void quisquilious_idiorrhythmy(int underplant_rotatoplane,tzetse_nonpyogenic emmenthal_unawakenedness)
{
    char *stonesoup_byte_4 = 0;
    char *stonesoup_byte_3 = 0;
    unsigned int *stonesoup_ptr = 0;
    struct stonesoup_struct ssS;
  char *maidu_launched = 0;
  ++stonesoup_global_variable;
  underplant_rotatoplane--;
  if (underplant_rotatoplane > 0) {
    quisquilious_idiorrhythmy(underplant_rotatoplane,emmenthal_unawakenedness);
    return ;
  }
  maidu_launched = ((char *)((tzetse_nonpyogenic )emmenthal_unawakenedness));
    tracepoint(stonesoup_trace, weakness_start, "CWE682", "B", "Incorrect Calculation");
    ssS.stonesoup_function_ptr_1 = stonesoup_function;
    ssS.stonesoup_function_ptr_2 = stonesoup_function;
    if (strlen(maidu_launched) >= 1 &&
            maidu_launched[0] != '-') {
        ssS.stonesoup_input_num = strtoul(maidu_launched,0U,16);
        stonesoup_ptr = &(ssS.stonesoup_input_num);
        if ( *stonesoup_ptr > 65535) {
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
            tracepoint(stonesoup_trace, variable_address, "(ssS.stonesoup_function_ptr_2)", (ssS.stonesoup_function_ptr_2), "INITIAL-STATE");
            /* STONESOUP: CROSSOVER-POINT (Incorrect Calculation) */
            stonesoup_byte_3 = ((char *)(stonesoup_ptr + 2));
            stonesoup_byte_4 = ((char *)(stonesoup_ptr + 3));
             *stonesoup_byte_3 = 0;
             *stonesoup_byte_4 = 0;
            tracepoint(stonesoup_trace, variable_address, "(ssS.stonesoup_function_ptr_2)", (ssS.stonesoup_function_ptr_2), "CROSSOVER-STATE");
            /* STONESOUP: CROSSOVER-POINT (Incorrect Calculation) */
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (Incorrect Calculation) */
        ssS.stonesoup_function_ptr_2();
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        stonesoup_printf("Value = %i\n", ssS.stonesoup_input_num);
    } else if (strlen(maidu_launched) == 0) {
        stonesoup_printf("Input is empty string\n");
    } else {
        stonesoup_printf("Input is negative number\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((tzetse_nonpyogenic )emmenthal_unawakenedness) != 0) 
    free(((char *)((tzetse_nonpyogenic )emmenthal_unawakenedness)));
stonesoup_close_printf_context();
}
