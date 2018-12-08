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
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
#include <math.h> 
#include <pthread.h> 
#include <signal.h> 
#include <unistd.h> 
static ts_type timestamp_type = TS_NOT_SET;
static int timestamp_precision = TS_PREC_AUTO_USEC;
static ts_seconds_type timestamp_seconds_type = TS_SECONDS_NOT_SET;
int inevidence_superequivalent = 0;
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
void averseness_gladless(int chingma_coembodied,char *seessel_semibelted);
struct stonesoup_data {
    int data_size;
    char *data;
    char *file1;
};
struct stonesoup_data *stonesoupData;
pthread_mutex_t stonesoup_mutex;
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpe9bmKp_ss_testcase/src-rose/epan/timestamp.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file");
}
void waitForSig(char* sleepFile) {
    int fd;
    char outStr[25] = {0};
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpe9bmKp_ss_testcase/src-rose/epan/timestamp.c", "waitForSig");
    stonesoup_printf("In waitForSig\n");
    sprintf(outStr, "%d.pid", getpid());
    strcat(filename, "/opt/stonesoup/workspace/testData/");
    strcat(filename, outStr);
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        tracepoint(stonesoup_trace, trace_error, "Error opening file.");
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            stonesoup_printf("Error writing to file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Wrote .pid file.");
        if (close(fd) == -1) {
            stonesoup_printf("Error closing file.");
        }
        stonesoup_readFile(sleepFile);
    }
}
void delNonAlpha (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*) data;
    int i = 0;
    int j = 0;
    char* temp = malloc(sizeof(char) * (stonesoupData->data_size + 1));
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpe9bmKp_ss_testcase/src-rose/epan/timestamp.c", "delNonAlpha");
    stonesoup_printf("Grabbing lock\n");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (nonreentrant signal handler) */
    pthread_mutex_lock(&stonesoup_mutex); /* mutex lock causes deadlock on re-entrance */
    tracepoint(stonesoup_trace, trace_point, "mutex locked");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    while(stonesoupData->data[i] != '\0') {
        if((stonesoupData->data[i] >= 'A' && stonesoupData->data[i] <= 'Z') ||
           (stonesoupData->data[i] >= 'a' && stonesoupData->data[i] <= 'z')) {
            temp[j++] = stonesoupData->data[i];
        }
        i++;
    }
    temp[j++] = '\0';
    stonesoupData->data_size = j;
    free(stonesoupData->data);
    stonesoupData->data = temp;
    waitForSig(stonesoupData->file1); /* Deadlock */
    stonesoup_printf("Realeasing lock\n");
    pthread_mutex_unlock(&stonesoup_mutex);
    tracepoint(stonesoup_trace, trace_point, "mutex unlocked");
}
void sig_handler (int sig) {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpe9bmKp_ss_testcase/src-rose/epan/timestamp.c", "sig_handler");
    /* STONESOUP: CROSSOVER-POINT (nonreentrentsighandler) */
    if (stonesoupData != NULL) {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        delNonAlpha(stonesoupData); /* call non-reentrant function - deadlock */
    }
    signal(SIGUSR1, SIG_IGN);
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
  int pirouettist_sunlit = 7;
  char *maying_pdl = 0;
  int *backvelder_thorin = 0;
  int sao_valorise;
  char *aimed_distracts[10] = {0};
  char *unweariably_manipulate;;
  if (__sync_bool_compare_and_swap(&inevidence_superequivalent,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpe9bmKp_ss_testcase/src-rose/epan/timestamp.c","timestamp_get_precision");
      stonesoup_setup_printf_context();
      unweariably_manipulate = getenv("MALEMIUT_DEINOCEPHALIA");
      if (unweariably_manipulate != 0) {;
        aimed_distracts[5] = unweariably_manipulate;
        sao_valorise = 5;
        backvelder_thorin = &sao_valorise;
        maying_pdl =  *(aimed_distracts +  *backvelder_thorin);
        averseness_gladless(pirouettist_sunlit,maying_pdl);
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

void averseness_gladless(int chingma_coembodied,char *seessel_semibelted)
{
  char *berendo_graperoot = 0;
  ++stonesoup_global_variable;
  chingma_coembodied--;
  if (chingma_coembodied > 0) {
    averseness_gladless(chingma_coembodied,seessel_semibelted);
    return ;
  }
  berendo_graperoot = ((char *)seessel_semibelted);
    tracepoint(stonesoup_trace, weakness_start, "CWE479", "A", "Signal Handler Use of a Non-reentrant Function");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(berendo_graperoot) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(berendo_graperoot) + 1));
        if (stonesoupData->data && stonesoupData->file1) {
            if ((sscanf(berendo_graperoot, "%s %s",
                        stonesoupData->file1,
                        stonesoupData->data) == 2) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0))
            {
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                stonesoupData->data_size = strlen(stonesoupData->data);
                if (pthread_mutex_init(&stonesoup_mutex, NULL) != 0) {
                    stonesoup_printf("Mutex failed to initilize.");
                 }
                if (signal(SIGUSR1, sig_handler) == SIG_ERR) { /* setup signal handler */
                    tracepoint(stonesoup_trace, trace_error, "Error setting up sig handler for SIGUSR1");
                    stonesoup_printf ("Error catching SIGUSR1!\n");
                }
                delNonAlpha(stonesoupData);
                signal(SIGUSR1, SIG_IGN); /* 'deregister' signal hander befor returning to base program */
            } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data");
                stonesoup_printf("Error parsing data\n");
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
