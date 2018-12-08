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
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <sys/types.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
int vicaire_passed = 0;
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
void gwelo_squelches(char *nabcheat_unregenerated);
void aedicule_undeniable(char *aldoxime_speckfall);
void charade_mitchiner(char *sylleptically_noonstead);
void octans_bespattered(char *cruiskeen_diduce);
void ulcerated_nokesville(char *cam_lotis);
void arrowroot_pentecostarion(char *hales_geraldine);
void ambitionless_unshadow(char *cryptomnesic_sorptions);
void teneral_dumbfounderment(char *bronchotomy_halvahs);
void chevise_postparotid(char *steepdown_scratchy);
void obtrusionist_contrastingly(char *beady_predevelop);
int stonesoup_search(char *str_param,char c_param)
{
    if ( *str_param == c_param) {
        return 1;
    } else if ( *str_param == 0) {
        /* STONESOUP: CROSSOVER-POINT (Uncontrolled Recursion) */
  /* STONESOUP: TRIGGER-POINT (Uncontrolled Recursion) */
  return stonesoup_search(&str_param[0],c_param);
    } else {
  return stonesoup_search(&str_param[1],c_param);
  }
}

unsigned int avdevice_version()
{
  char *berliner_tristate = 0;
  int *bringela_overcare = 0;
  int unkindest_sportly;
  char *peopled_lewiston[10] = {0};
  int acecaffine_sheldfowl = 0;
  char *zaramo_obviations = 0;
  int seaworn_bertolde = 31;
  char *needlebill_nondevoutly;;
  if (__sync_bool_compare_and_swap(&vicaire_passed,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpjPDSPG_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&needlebill_nondevoutly,"4236",seaworn_bertolde);
      if (needlebill_nondevoutly != 0) {;
        acecaffine_sheldfowl = ((int )(strlen(needlebill_nondevoutly)));
        zaramo_obviations = ((char *)(malloc(acecaffine_sheldfowl + 1)));
        if (zaramo_obviations == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(zaramo_obviations,0,acecaffine_sheldfowl + 1);
        memcpy(zaramo_obviations,needlebill_nondevoutly,acecaffine_sheldfowl);
        if (needlebill_nondevoutly != 0) 
          free(((char *)needlebill_nondevoutly));
        peopled_lewiston[5] = zaramo_obviations;
        unkindest_sportly = 5;
        bringela_overcare = &unkindest_sportly;
        berliner_tristate =  *(peopled_lewiston +  *bringela_overcare);
        gwelo_squelches(berliner_tristate);
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

void gwelo_squelches(char *nabcheat_unregenerated)
{
  ++stonesoup_global_variable;;
  aedicule_undeniable(nabcheat_unregenerated);
}

void aedicule_undeniable(char *aldoxime_speckfall)
{
  ++stonesoup_global_variable;;
  charade_mitchiner(aldoxime_speckfall);
}

void charade_mitchiner(char *sylleptically_noonstead)
{
  ++stonesoup_global_variable;;
  octans_bespattered(sylleptically_noonstead);
}

void octans_bespattered(char *cruiskeen_diduce)
{
  ++stonesoup_global_variable;;
  ulcerated_nokesville(cruiskeen_diduce);
}

void ulcerated_nokesville(char *cam_lotis)
{
  ++stonesoup_global_variable;;
  arrowroot_pentecostarion(cam_lotis);
}

void arrowroot_pentecostarion(char *hales_geraldine)
{
  ++stonesoup_global_variable;;
  ambitionless_unshadow(hales_geraldine);
}

void ambitionless_unshadow(char *cryptomnesic_sorptions)
{
  ++stonesoup_global_variable;;
  teneral_dumbfounderment(cryptomnesic_sorptions);
}

void teneral_dumbfounderment(char *bronchotomy_halvahs)
{
  ++stonesoup_global_variable;;
  chevise_postparotid(bronchotomy_halvahs);
}

void chevise_postparotid(char *steepdown_scratchy)
{
  ++stonesoup_global_variable;;
  obtrusionist_contrastingly(steepdown_scratchy);
}

void obtrusionist_contrastingly(char *beady_predevelop)
{
 int stonesoup_found;
  char *sayonara_nonvocational = 0;
  ++stonesoup_global_variable;;
  sayonara_nonvocational = ((char *)beady_predevelop);
    tracepoint(stonesoup_trace, weakness_start, "CWE674", "A", "Uncontrolled Recursion");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    stonesoup_found = stonesoup_search(&sayonara_nonvocational[1],sayonara_nonvocational[0]);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, weakness_end);
;
  if (beady_predevelop != 0) 
    free(((char *)beady_predevelop));
stonesoup_close_printf_context();
}
