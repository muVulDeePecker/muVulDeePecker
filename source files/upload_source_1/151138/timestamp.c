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
#include <setjmp.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <limits.h> 
static ts_type timestamp_type = TS_NOT_SET;
static int timestamp_precision = TS_PREC_AUTO_USEC;
static ts_seconds_type timestamp_seconds_type = TS_SECONDS_NOT_SET;
int onegite_eumorphic = 0;
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
int stonesoup_190_global_var = 0;

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
    int stonesoup_tainted_int = 0;
    int stonesoup_output_counter = 0;
  char *badin_marilyn = 0;
  jmp_buf circulations_spondylous;
  int disadventure_sumo;
  char **epilating_dreggiest = 0;
  long kurbashed_ophiolitic[10];
  char **aotearoa_sadducize[10] = {0};
  char *hebraists_dipetto[15] = {0};
  int arachne_flensburg = 6;
  char *reinvested_blessedly;;
  if (__sync_bool_compare_and_swap(&onegite_eumorphic,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpAvzRhe_ss_testcase/src-rose/epan/timestamp.c","timestamp_get_precision");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&reinvested_blessedly,"8669",arachne_flensburg);
      if (reinvested_blessedly != 0) {;
        hebraists_dipetto[3] = reinvested_blessedly;
        aotearoa_sadducize[5] = hebraists_dipetto;
        kurbashed_ophiolitic[1] = 5;
        epilating_dreggiest =  *(aotearoa_sadducize + kurbashed_ophiolitic[1]);
        disadventure_sumo = setjmp(circulations_spondylous);
        if (disadventure_sumo == 0) {
          longjmp(circulations_spondylous,1);
        }
        badin_marilyn = ((char *)epilating_dreggiest[3]);
    tracepoint(stonesoup_trace, weakness_start, "CWE190", "A", "Integer Overflow or Wraparound");
    stonesoup_tainted_int = atoi(badin_marilyn);
    if (stonesoup_tainted_int > 0) {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Integer Overflow) */
        stonesoup_tainted_int = stonesoup_tainted_int * stonesoup_tainted_int;
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_tainted_int", stonesoup_tainted_int, &stonesoup_tainted_int, "TRIGGER-STATE");
        while (stonesoup_tainted_int != 0) {
/* STONESOUP: TRIGGER-POINT (Integer Overflow) */
            if (stonesoup_tainted_int != INT_MIN) {
                stonesoup_tainted_int--;
            }
            /* Output only once every million iterations */
            if (stonesoup_output_counter == 0) {
                stonesoup_printf("evaluating input\n");
            }
            stonesoup_output_counter++;
            if (stonesoup_output_counter == 1000000) {
                stonesoup_output_counter = 0;
            }
            ++stonesoup_190_global_var;
            if (stonesoup_190_global_var >= INT_MAX) {
                stonesoup_190_global_var = 0;
            }
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    }
    stonesoup_printf("finished evaluating\n");
    tracepoint(stonesoup_trace, weakness_end);
;
        if (epilating_dreggiest[3] != 0) 
          free(((char *)epilating_dreggiest[3]));
stonesoup_close_printf_context();
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
