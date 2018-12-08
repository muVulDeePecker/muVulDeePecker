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
#include <stdarg.h> 
#include <stonesoup/stonesoup_trace.h> 
int zymoid_radiolocators = 0;
int stonesoup_global_variable;

union mameliere_moderant 
{
  char *unnymphal_stenopeic;
  double fanback_scarify;
  char *homeoplasy_semimarking;
  char nonprofanely_nonprossing;
  int albertine_bondship;
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
void redshift_whiggish(int conchuela_leibnitz,... );

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
  union mameliere_moderant cowtail_obelism;
  char *homos_theistically;;
  if (__sync_bool_compare_and_swap(&zymoid_radiolocators,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpfbpCfQ_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c","oid_hash");
      stonesoup_setup_printf_context();
      homos_theistically = getenv("HALFPENCE_FESTA");
      if (homos_theistically != 0) {;
        cowtail_obelism . unnymphal_stenopeic = homos_theistically;
        redshift_whiggish(1,cowtail_obelism);
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

void redshift_whiggish(int conchuela_leibnitz,... )
{
  char stonesoup_buffer[100];
  FILE *stonesoup_fpipe = 0;
  char stonesoup_cmd_string[1000] = {0};
  int stonesoup_is_valid = 1;
  int stonesoup_i = 0;
  char stonesoup_base_cmd[1000];
  char *wished_ravenelia = 0;
  union mameliere_moderant padres_brachet = {0};
  va_list sphaeriaceae_withcall;
  ++stonesoup_global_variable;;
  if (conchuela_leibnitz > 0) {
    __builtin_va_start(sphaeriaceae_withcall,conchuela_leibnitz);
    padres_brachet = (va_arg(sphaeriaceae_withcall,union mameliere_moderant ));
    __builtin_va_end(sphaeriaceae_withcall);
  }
  wished_ravenelia = ((char *)padres_brachet . unnymphal_stenopeic);
    tracepoint(stonesoup_trace, weakness_start, "CWE088", "A", "Argument Injection or Modification");
    snprintf(stonesoup_base_cmd, 1000, "find %s -iname ", "/opt/stonesoup/workspace/testData/temp" );
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_base_cmd", stonesoup_base_cmd, "INITIAL STATE");
    for (; stonesoup_i < strlen(wished_ravenelia); ++stonesoup_i) {
        if (wished_ravenelia[stonesoup_i] == ';') {
          if (stonesoup_i == 0 || wished_ravenelia[stonesoup_i - 1] != '\\') {
            stonesoup_is_valid = 0;
            break;
          }
        }
      }
      if (stonesoup_is_valid == 1) {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Argument Injection) */
        snprintf(stonesoup_cmd_string,1000,"%s%s",stonesoup_base_cmd,wished_ravenelia);
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_cmd_string", stonesoup_cmd_string, "CROSSOVER-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Argument Injection) */
        stonesoup_fpipe = popen(stonesoup_cmd_string,"r");
        if (stonesoup_fpipe != 0) {
            while(fgets(stonesoup_buffer,100,stonesoup_fpipe) != 0) {
              stonesoup_printf(stonesoup_buffer);
              }
          pclose(stonesoup_fpipe);
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      }
      tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
