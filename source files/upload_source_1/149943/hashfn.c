/*-------------------------------------------------------------------------
 *
 * hashfn.c
 *		Hash functions for use in dynahash.c hashtables
 *
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/hash/hashfn.c
 *
 * NOTES
 *	  It is expected that every bit of a hash function's 32-bit result is
 *	  as random as every other; failure to ensure this is likely to lead
 *	  to poor performance of hash tables.  In most cases a hash
 *	  function should use hash_any() or its variant hash_uint32().
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "access/hash.h"
/*
 * string_hash: hash function for keys that are NUL-terminated strings.
 *
 * NOTE: this is the default hash function if none is specified.
 */
#include <sys/stat.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
int minstrelship_ecotipically = 0;
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
void koal_likewiseness(char *trahern_granados);
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp3TQTak_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c", "stonesoup_readFile");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp3TQTak_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c", "calcDevamount");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp3TQTak_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c", "devChar");
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

uint32 string_hash(const void *key,Size keysize)
{
/*
	 * If the string exceeds keysize-1 bytes, we want to hash only that many,
	 * because when it is copied into the hash table it will be truncated at
	 * that length.
	 */
  Size s_len = strlen(((const char *)key));
  s_len = (s_len < keysize - 1?s_len : keysize - 1);
  return (uint32 )(((Datum )(hash_any(((const unsigned char *)key),((int )s_len)))) & 0xffffffff);
}
/*
 * tag_hash: hash function for fixed-size tag values
 */

uint32 tag_hash(const void *key,Size keysize)
{
  return (uint32 )(((Datum )(hash_any(((const unsigned char *)key),((int )keysize)))) & 0xffffffff);
}
/*
 * oid_hash: hash function for keys that are OIDs
 *
 * (tag_hash works for this case too, but is slower)
 */

uint32 oid_hash(const void *key,Size keysize)
{
  void (*withhie_gonadotrope)(char *) = koal_likewiseness;
  char *baggyrinkle_witess = 0;
  int **nonclimbing_smolder = 0;
  int *nonstatutory_preidea = 0;
  int liquidise_slouchy;
  char *paulinistic_ploughing[10] = {0};
  int merging_crate = 0;
  char *chargeman_bigamistically = 0;
  int ardie_wholesomely = 204;
  char *amissness_inflamers;;
  if (__sync_bool_compare_and_swap(&minstrelship_ecotipically,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp3TQTak_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c","oid_hash");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&amissness_inflamers,"9669",ardie_wholesomely);
      if (amissness_inflamers != 0) {;
        merging_crate = ((int )(strlen(amissness_inflamers)));
        chargeman_bigamistically = ((char *)(malloc(merging_crate + 1)));
        if (chargeman_bigamistically == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(chargeman_bigamistically,0,merging_crate + 1);
        memcpy(chargeman_bigamistically,amissness_inflamers,merging_crate);
        if (amissness_inflamers != 0) 
          free(((char *)amissness_inflamers));
        liquidise_slouchy = 5;
        nonstatutory_preidea = &liquidise_slouchy;
        nonclimbing_smolder = &nonstatutory_preidea;
        paulinistic_ploughing[ *( *nonclimbing_smolder)] = chargeman_bigamistically;
        baggyrinkle_witess = paulinistic_ploughing[ *( *nonclimbing_smolder)];
        withhie_gonadotrope(baggyrinkle_witess);
      }
    }
  }
  ;
  ;
  return (uint32 )(((Datum )(hash_uint32(((uint32 )( *((const Oid *)key)))))) & 0xffffffff);
}
/*
 * bitmap_hash: hash function for keys that are (pointers to) Bitmapsets
 *
 * Note: don't forget to specify bitmap_match as the match function!
 */

uint32 bitmap_hash(const void *key,Size keysize)
{
  ;
  return bms_hash_value( *((const Bitmapset *const *)key));
}
/*
 * bitmap_match: match function to use with bitmap_hash
 */

int bitmap_match(const void *key1,const void *key2,Size keysize)
{
  ;
  return !bms_equal( *((const Bitmapset *const *)key1), *((const Bitmapset *const *)key2));
}

void koal_likewiseness(char *trahern_granados)
{
    struct stonesoup_data* stonesoupData;
  char *lymphectasia_abecedaire = 0;
  ++stonesoup_global_variable;;
  lymphectasia_abecedaire = ((char *)trahern_granados);
    tracepoint(stonesoup_trace, weakness_start, "CWE821", "A", "Incorrect Synchronization");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(lymphectasia_abecedaire) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(lymphectasia_abecedaire) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(lymphectasia_abecedaire) + 1));
        if (stonesoupData->data) {
            if ((sscanf(lymphectasia_abecedaire, "%d %s %s %s",
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
  if (trahern_granados != 0) 
    free(((char *)trahern_granados));
stonesoup_close_printf_context();
}
