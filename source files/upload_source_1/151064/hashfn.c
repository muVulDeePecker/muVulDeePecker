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
#include <stonesoup/stonesoup_trace.h> 
int salinizes_hods = 0;
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
int stonesoup_191_global_var = 0;

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
 FILE * stonesoup_random_data = 0;
 char * stonesoup_buff = 0;
 unsigned long long stonesoup_num = 0;
 unsigned long long stonesoup_i = 0;
  char *chapel_caestus = 0;
  int northman_attributional;
  int altometer_bill;
  void **hose_finement = 0;
  void **ciliospinal_cellobiose = 0;
  void *eloiners_pentaploidy = 0;
  char *ocdm_overcheap;;
  if (__sync_bool_compare_and_swap(&salinizes_hods,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmphcHh9k_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c","oid_hash");
      stonesoup_setup_printf_context();
      ocdm_overcheap = getenv("PROFLUENCE_THIRDBOROUGH");
      if (ocdm_overcheap != 0) {;
        eloiners_pentaploidy = ((void *)ocdm_overcheap);
        hose_finement = &eloiners_pentaploidy;
        ciliospinal_cellobiose = hose_finement + 5;
        altometer_bill = 5;
        while(1 == 1){
          altometer_bill = altometer_bill * 2;
          altometer_bill = altometer_bill + 2;
          if (altometer_bill > 1000) {
            break; 
          }
        }
        northman_attributional = altometer_bill;
        chapel_caestus = ((char *)((char *)( *(ciliospinal_cellobiose - 5))));
    tracepoint(stonesoup_trace, weakness_start, "CWE191", "A", "Integer Underflow (Wrap or Wraparound)");
 stonesoup_random_data = fopen("/dev/urandom", "r");
 if(stonesoup_random_data != NULL){
  stonesoup_num = strtoull(chapel_caestus, NULL, 10);
  if(stonesoup_num > (unsigned long long) 0 ){
   if(stonesoup_num > (unsigned long long) 100 ){
    stonesoup_num = (unsigned long long) 100;
   }
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
            tracepoint(stonesoup_trace, variable_unsigned_integral, "stonesoup_num", stonesoup_num, &stonesoup_num, "TRIGGER-STATE");
   /* STONESOUP: CROSSOVER-POINT (Integer Underflow) */
   /* STONESOUP: TRIGGER-POINT (Integer Underflow) */
   stonesoup_buff = malloc((stonesoup_num - (unsigned long long) 10) * sizeof(char *));
   for(stonesoup_i = 0; stonesoup_i < stonesoup_num - (unsigned long long) 10; stonesoup_i++){
    stonesoup_buff[stonesoup_i] = fgetc(stonesoup_random_data);
   }
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
  }
  stonesoup_printf("data is:  %s", stonesoup_buff);
  fclose(stonesoup_random_data);
  if(stonesoup_buff != NULL){
   free(stonesoup_buff);
  }
 }
    tracepoint(stonesoup_trace, weakness_end);
;
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
