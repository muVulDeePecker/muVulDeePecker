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
#include <libpq-fe.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <dlfcn.h> 
int stingbull_muscidae = 0;
int stonesoup_global_variable;

struct presocialism_particularised 
{
  char *deletive_unsupplicating;
  double neurotropy_forepeak;
  char *calyptriform_unrejoicing;
  char reenlighten_gonadectomy;
  int posteens_skeins;
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
struct presocialism_particularised debugged_nonrelativeness(struct presocialism_particularised wroken_hool);
#define GRAPTOLITOIDEA_CATEGORIZATION(x) cleansers_zacata((struct presocialism_particularised) x)
void cleansers_zacata(struct presocialism_particularised bebouldered_tubinares);

unsigned int avdevice_version()
{
  struct presocialism_particularised barghests_nominated = {0};
  struct presocialism_particularised rewelcome_schizophrene;
  char *cakchikel_ensculpture;;
  if (__sync_bool_compare_and_swap(&stingbull_muscidae,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpSH5jFP_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      stonesoup_setup_printf_context();
      cakchikel_ensculpture = getenv("GUMBOILS_CARES");
      if (cakchikel_ensculpture != 0) {;
        rewelcome_schizophrene . deletive_unsupplicating = ((char *)cakchikel_ensculpture);
        barghests_nominated = debugged_nonrelativeness(rewelcome_schizophrene);
	GRAPTOLITOIDEA_CATEGORIZATION(barghests_nominated);
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
  return "--prefix=/opt/stonesoup/workspace/install --enable-pic --disable-static --enable-shared --disable-yasm --disable-doc --enable-pthreads --disable-w32threads --disable-os2threads --enable-zlib --enable-openssl --disable-asm --extra-cflags= --extra-ldflags= --extra-libs='-lssl -lpq -ldl'";
}

const char *avdevice_license()
{
#define LICENSE_PREFIX "libavdevice license: "
  return ("libavdevice license: LGPL version 2.1 or later" + sizeof("libavdevice license: ") - 1);
}

struct presocialism_particularised debugged_nonrelativeness(struct presocialism_particularised wroken_hool)
{
  ++stonesoup_global_variable;
  return wroken_hool;
}

void cleansers_zacata(struct presocialism_particularised bebouldered_tubinares)
{
    PGresult *res = 0;
    char query[1000];
    PGconn *conn = 0;
    char dbconn_str[150];
    char *dbport = 0;
    char *dbpassword = 0;
    char *dbuser = 0;
    char *dbhost = 0;
    char *dbdatabase = 0;
    int stonesoup_nFields;
    int stonesoup_i;
    int stonesoup_j = 0;
  char *soliloquacious_alep = 0;
  ++stonesoup_global_variable;;
  soliloquacious_alep = ((char *)bebouldered_tubinares . deletive_unsupplicating);
    tracepoint(stonesoup_trace, weakness_start, "CWE089", "B", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')");
    dbhost = getenv("DBPGHOST");
    dbuser = getenv("DBPGUSER");
    dbpassword = getenv("DBPGPASSWORD");
    dbport = getenv("DBPGPORT");
    dbdatabase = getenv("SS_DBPGDATABASE");
    tracepoint(stonesoup_trace, variable_buffer, "dbhost", dbhost, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbuser", dbuser, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbpassword", dbpassword, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbport", dbport, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbdatabase", dbdatabase, "INITIAL-STATE");
    if (dbhost != 0 && dbport != 0 && dbuser != 0 && dbpassword != 0 && dbdatabase != 0) {
        snprintf(dbconn_str,150,"dbname=%s host=%s user=%s password=%s port=%s",
            dbdatabase, dbhost, dbuser, dbpassword, dbport);
        conn = PQconnectdb(dbconn_str);
        if (PQstatus(conn) != 0) {
            tracepoint(stonesoup_trace, trace_error, "Connection to database failed.");
            stonesoup_printf("%s: %s\n","Connection to database failed", PQerrorMessage(conn));
            PQfinish(conn);
            exit(1);
        }
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        /* STONESOUP: CROSSOVER-POINT (Sql Injection) */
        snprintf(query,1000,"SELECT * FROM customers WHERE \"country\" = '%s';", soliloquacious_alep);
        tracepoint(stonesoup_trace, variable_buffer, "query", query, "CROSSOVER-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (Sql Injection) */
        res = PQexec(conn,query);
        if (PQresultStatus(res) != 2) {
            tracepoint(stonesoup_trace, trace_error, "Select failed.");
            stonesoup_printf("%s: %s\n","SELECT failed",PQerrorMessage(conn));
            PQclear(res);
            PQfinish(conn);
            exit(1);
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        /* first, print out the attribute names */
        stonesoup_nFields = PQnfields(res);
        for (stonesoup_i = 0; stonesoup_i < stonesoup_nFields; stonesoup_i++)
            stonesoup_printf("%-15s", PQfname(res, stonesoup_i));
        stonesoup_printf("\n\n");
        /* next, print out the rows */
        for (stonesoup_i = 0; stonesoup_i < PQntuples(res); stonesoup_i++)
        {
            for (stonesoup_j = 0; stonesoup_j < stonesoup_nFields; stonesoup_j++)
                stonesoup_printf("%-15s", PQgetvalue(res, stonesoup_i, stonesoup_j));
            stonesoup_printf("\n");
        }
        PQclear(res);
        PQfinish(conn);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
