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
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
int impale_mackling = 0;
int stonesoup_global_variable;

union leavitt_dielectrics 
{
  char *uncrossly_rinning;
  double surrealist_unswept;
  char *kashruths_plethodon;
  char cliffhang_omnipotently;
  int inflammatorily_nonbachelor;
}
;
#define HARPINA_MISCONDUCTED(x) plumerville_gorgonlike((union leavitt_dielectrics *) x)
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
void plumerville_gorgonlike(union leavitt_dielectrics *dollia_complexionably);
struct stonesoup_data {
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
pthread_t stonesoup_t0, stonesoup_t1;
pthread_mutex_t stonesoup_mutex_0, stonesoup_mutex_1;
int stonesoup_dev_amount = 1;
int stonesoup_comp (const void * a, const void * b) {
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
int stonesoup_pmoc (const void * a, const void * b) {
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0qqSLp_ss_testcase/src-rose/libavdevice/avdevice.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void *calcDevamount(void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int qsize;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0qqSLp_ss_testcase/src-rose/libavdevice/avdevice.c", "calcDevamount");
    stonesoup_printf("Inside calcDevAmount\n");
    pthread_mutex_lock(&stonesoup_mutex_0);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    /* STONESOUP: CROSSOVER-POINT (incorrect syncronization) */
    stonesoup_dev_amount = stonesoupData->data[0] - 'A'; /* oops...um... */
    qsize = stonesoupData->qsize;
    if (stonesoup_dev_amount < 0) { /* let's just clean up and */
        stonesoup_dev_amount *= -1; /*  pretend that never happened */
    }
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_dev_amount", stonesoup_dev_amount, &stonesoup_dev_amount, "CROSSOVER-STATE");
    stonesoup_readFile(stonesoupData->file2);
    if (stonesoup_dev_amount == 0) { /* shhhh, just some more cleanup */
        stonesoup_dev_amount += 1; /*  nothing to see here */
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-PONT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_dev_amount", stonesoup_dev_amount, &stonesoup_dev_amount, "FINAL-STATE");
    pthread_mutex_unlock(&stonesoup_mutex_0);
    return NULL;
}
void *devChar(void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int stonesoup_i;
    int i;
    int *stonesoup_arr = NULL;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0qqSLp_ss_testcase/src-rose/libavdevice/avdevice.c", "devChar");
    stonesoup_printf("Inside devChar\n");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int) * stonesoupData->qsize);
    pthread_mutex_lock(&stonesoup_mutex_1);
    for (stonesoup_i = 0; stonesoup_i < stonesoupData->qsize; stonesoup_i++) {
        stonesoup_arr[stonesoup_i] = stonesoupData->qsize - stonesoup_i;
    }
    qsort(stonesoup_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
    free(stonesoup_arr);
    stonesoup_readFile(stonesoupData->file1);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_dev_amount", stonesoup_dev_amount, &stonesoup_dev_amount, "TRIGGER-STATE");
    /* STONESOUP: TRIGGER-POINT (incorrect syncronization) */
    for (i = 0; i < strlen(stonesoupData->data); i++) { /* can cause underread/write if */
        stonesoupData->data[i] /= stonesoup_dev_amount; /*  stonesoup_dev_amount is neg */
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    pthread_mutex_unlock(&stonesoup_mutex_1);
    return NULL;
}

unsigned int avdevice_version()
{
  union leavitt_dielectrics *nonextenuatory_hepatectomizing = {0};
  union leavitt_dielectrics *neckful_razors = {0};
  union leavitt_dielectrics ribston_arbuthnot;
  int quod_solea = 204;
  char *masseteric_foldage;;
  if (__sync_bool_compare_and_swap(&impale_mackling,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp0qqSLp_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&masseteric_foldage,"9364",quod_solea);
      if (masseteric_foldage != 0) {;
        ribston_arbuthnot . uncrossly_rinning = masseteric_foldage;
        nonextenuatory_hepatectomizing = &ribston_arbuthnot;
        neckful_razors = nonextenuatory_hepatectomizing + 5;
	HARPINA_MISCONDUCTED(neckful_razors);
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
  return "--prefix=/opt/stonesoup/workspace/install --enable-pic --disable-static --enable-shared --disable-yasm --disable-doc --enable-pthreads --disable-w32threads --disable-os2threads --enable-zlib --enable-openssl --disable-asm --extra-cflags= --extra-ldflags= --extra-libs='-lpthread -ldl'";
}

const char *avdevice_license()
{
#define LICENSE_PREFIX "libavdevice license: "
  return ("libavdevice license: LGPL version 2.1 or later" + sizeof("libavdevice license: ") - 1);
}

void plumerville_gorgonlike(union leavitt_dielectrics *dollia_complexionably)
{
    struct stonesoup_data* stonesoupData;
  char *thrilliest_swiftlike = 0;
  ++stonesoup_global_variable;;
  thrilliest_swiftlike = ((char *)( *(dollia_complexionably - 5)) . uncrossly_rinning);
    tracepoint(stonesoup_trace, weakness_start, "CWE821", "A", "Incorrect Synchronization");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(thrilliest_swiftlike) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(thrilliest_swiftlike) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(thrilliest_swiftlike) + 1));
        if (stonesoupData->data) {
            if ((sscanf(thrilliest_swiftlike, "%d %s %s %s",
                      &(stonesoupData->qsize),
                        stonesoupData->file1,
                        stonesoupData->file2,
                        stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0) &&
                (strlen(stonesoupData->file2) != 0))
            {
                pthread_mutex_init(&stonesoup_mutex_0, NULL);
                pthread_mutex_init(&stonesoup_mutex_1, NULL);
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
                tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
                if (strlen(stonesoupData->data) > 50) { /* if size is large */
                                                                                                    /*  iterate by different */
                    if (pthread_create(&stonesoup_t0, NULL, calcDevamount, stonesoupData) != 0) { /*  size (weakness). */
                        stonesoup_printf("Error initializing thread 0.");
                    }
                }
                if (pthread_create(&stonesoup_t1, NULL, devChar, stonesoupData) != 0) {
                    stonesoup_printf("Error initializing thread 1.");
                }
                if (strlen(stonesoupData->data) > 50) {
                    pthread_join(stonesoup_t0, NULL);
                }
                pthread_join(stonesoup_t1, NULL);
                tracepoint(stonesoup_trace, trace_point, "Threads joined.");
                pthread_mutex_destroy(&stonesoup_mutex_0);
                pthread_mutex_destroy(&stonesoup_mutex_1);
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
  if (( *(dollia_complexionably - 5)) . uncrossly_rinning != 0) 
    free(((char *)( *(dollia_complexionably - 5)) . uncrossly_rinning));
stonesoup_close_printf_context();
}
