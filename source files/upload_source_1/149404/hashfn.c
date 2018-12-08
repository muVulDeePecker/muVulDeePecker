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
#include <stonesoup/stonesoup_trace.h> 
int ordinariness_oxysomes = 0;

union unrealities_jewelhouse 
{
  char *thalamophora_carenton;
  double dhaka_neukam;
  char *pratincole_countrieman;
  char preimitated_keratomycosis;
  int feminine_hup;
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
int stonesoup_476_global_variable = 0;
int stonesoup_isalnum(int c)
{
  if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57)) {
    return 1;
  }
  return 0;
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
  char *stonesoup_second_buff = 0;
  int stonesoup_size = 0;
  char *folliculous_vamped = 0;
  int rifton_cheerio;
  int settimo_bassness;
  int blastemata_gda;
  union unrealities_jewelhouse *hld_overproudly = {0};
  union unrealities_jewelhouse *nematognath_gracy = {0};
  union unrealities_jewelhouse attical_beswelter;
  int desterilize_onychium = 63;
  char *prebroadcasting_auxiliation;;
  if (__sync_bool_compare_and_swap(&ordinariness_oxysomes,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp3RbHNd_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c","oid_hash");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&prebroadcasting_auxiliation,"1313",desterilize_onychium);
      if (prebroadcasting_auxiliation != 0) {;
        attical_beswelter . thalamophora_carenton = prebroadcasting_auxiliation;
        blastemata_gda = 1;
        hld_overproudly = &attical_beswelter;
        nematognath_gracy = ((union unrealities_jewelhouse *)(((unsigned long )hld_overproudly) * blastemata_gda * blastemata_gda)) + 5;
        settimo_bassness = 5;
        while(1 == 1){
          settimo_bassness = settimo_bassness * 2;
          settimo_bassness = settimo_bassness + 2;
          if (settimo_bassness > 1000) {
            break; 
          }
        }
        rifton_cheerio = settimo_bassness;
        folliculous_vamped = ((char *)( *(nematognath_gracy - 5)) . thalamophora_carenton);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "D", "NULL Pointer Dereference");
      while(stonesoup_isalnum(folliculous_vamped[stonesoup_size]) && stonesoup_size < strlen(folliculous_vamped)){
        ++stonesoup_size;
      }
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Null Pointer Dereference) */
      if (stonesoup_size != strlen(folliculous_vamped)) {
        folliculous_vamped = 0;
      }
      tracepoint(stonesoup_trace, variable_address, "STONESOUP_TAINT_SOURCE", folliculous_vamped, "CROSSOVER-STATE");
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      stonesoup_second_buff = malloc((stonesoup_size + 1) * sizeof(char ));
      if (stonesoup_second_buff == 0) {
        stonesoup_printf("Error: Failed to allocate memory\n");
        exit(1);
      }
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference) */
      strcpy(stonesoup_second_buff,folliculous_vamped);
      stonesoup_476_global_variable = strlen(stonesoup_second_buff);
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      ++stonesoup_476_global_variable;
      if (stonesoup_second_buff != 0) {
        free(stonesoup_second_buff);
      }
      stonesoup_printf("String contains only alpha numeric characters\n");
      tracepoint(stonesoup_trace, weakness_end);
;
        if (( *(nematognath_gracy - 5)) . thalamophora_carenton != 0) 
          free(((char *)( *(nematognath_gracy - 5)) . thalamophora_carenton));
stonesoup_close_printf_context();
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
