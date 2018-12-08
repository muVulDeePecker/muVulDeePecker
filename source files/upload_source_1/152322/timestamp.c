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
#include <libpq-fe.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <dlfcn.h> 
#include <time.h> 
static ts_type timestamp_type = TS_NOT_SET;
static int timestamp_precision = TS_PREC_AUTO_USEC;
static ts_seconds_type timestamp_seconds_type = TS_SECONDS_NOT_SET;
int borax_tattooed = 0;
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
void stonesoup_read_taint(char** stonesoup_tainted_buff, char* stonesoup_env_var_name) {
  if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
      strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
        char* stonesoup_tainted_file_name = 0;
        FILE * stonesoup_tainted_file = 0;
        size_t stonesoup_result = 0;
        long stonesoup_lsize = 0;
        stonesoup_tainted_file_name = getenv(stonesoup_env_var_name);
        stonesoup_tainted_file = fopen(stonesoup_tainted_file_name,"rb");
        if (stonesoup_tainted_file != 0) {
            fseek(stonesoup_tainted_file,0L,2);
            stonesoup_lsize = ftell(stonesoup_tainted_file);
            rewind(stonesoup_tainted_file);
            *stonesoup_tainted_buff = ((char *)(malloc(sizeof(char ) * (stonesoup_lsize + 1))));
            if (*stonesoup_tainted_buff != 0) {
                /* STONESOUP: SOURCE-TAINT (File Contents) */
                stonesoup_result = fread(*stonesoup_tainted_buff,1,stonesoup_lsize,stonesoup_tainted_file);
                (*stonesoup_tainted_buff)[stonesoup_lsize] = '\0';
            }
        }
        if (stonesoup_tainted_file != 0) {
            fclose(stonesoup_tainted_file);
        }
    } else {
        *stonesoup_tainted_buff = NULL;
    }
}
void gigs_chanhassen(char **clubhouses_unauthorized);

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
  void (*histochemically_bubblement)(char **) = gigs_chanhassen;
  char **alewife_chooky = 0;
  int lecher_leatherwood = 0;
  char *rollinia_implosions = 0;
  char *dogmata_achroodextrin;;
  if (__sync_bool_compare_and_swap(&borax_tattooed,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp5V5Gxy_ss_testcase/src-rose/epan/timestamp.c","timestamp_get_precision");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&dogmata_achroodextrin,"CONIOSES_SAILBOAT");
      if (dogmata_achroodextrin != 0) {;
        lecher_leatherwood = ((int )(strlen(dogmata_achroodextrin)));
        rollinia_implosions = ((char *)(malloc(lecher_leatherwood + 1)));
        if (rollinia_implosions == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(rollinia_implosions,0,lecher_leatherwood + 1);
        memcpy(rollinia_implosions,dogmata_achroodextrin,lecher_leatherwood);
        if (dogmata_achroodextrin != 0) 
          free(((char *)dogmata_achroodextrin));
        alewife_chooky = &rollinia_implosions;
        histochemically_bubblement(alewife_chooky);
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

void gigs_chanhassen(char **clubhouses_unauthorized)
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
    char *stonesoup_result = 0;
    int stonesoup_random_int = 0;
  char *browis_reenlisted = 0;
  ++stonesoup_global_variable;;
  browis_reenlisted = ((char *)( *clubhouses_unauthorized));
    tracepoint(stonesoup_trace, weakness_start, "CWE089", "D", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')");
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
  srand(time(NULL));
  stonesoup_random_int = (rand() % 1000) + 100;
        snprintf(query,1000,"INSERT INTO shippers (shipperid, companyname) VALUES ('%d', '%s');", stonesoup_random_int, browis_reenlisted);
        tracepoint(stonesoup_trace, variable_buffer, "query", query, "CROSSOVER-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (Sql Injection) */
        res = PQexec(conn,query);
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            tracepoint(stonesoup_trace, trace_error, "Insert failed.");
            stonesoup_printf("%s: %s\n","INSERT failed",PQerrorMessage(conn));
            PQclear(res);
            PQfinish(conn);
            exit(1);
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        /* Print out the Success of the command */
  stonesoup_result = PQcmdTuples(res);
        stonesoup_printf("Query OK, %s rows affected\n",stonesoup_result);
        PQclear(res);
        PQfinish(conn);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if ( *clubhouses_unauthorized != 0) 
    free(((char *)( *clubhouses_unauthorized)));
stonesoup_close_printf_context();
}
