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
#include <mongoose.h> 
#include <string.h> 
#include <stdarg.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <errno.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <sys/stat.h> 
static ts_type timestamp_type = TS_NOT_SET;
static int timestamp_precision = TS_PREC_AUTO_USEC;
static ts_seconds_type timestamp_seconds_type = TS_SECONDS_NOT_SET;
int unchurches_biblheb = 0;

union unsharing_schoolma 
{
  char *nonseparable_grenelle;
  double proterandrous_oxygenicity;
  char *octine_lucre;
  char deathtraps_italianish;
  int ironbound_endoclinal;
}
;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *clangoured_ukiyoye);
void* stonesoup_printf_context;
void stonesoup_setup_printf_context() {
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    // mg_send_header(stonesoup_printf_context, "Content-Type", "text/plain");
    va_start(argptr, format);
    mg_vprintf_data((struct mg_connection*) stonesoup_printf_context, format, argptr);
    va_end(argptr);
}
void stonesoup_close_printf_context() {
}
static int stonesoup_exit_flag = 0;
static int stonesoup_ev_handler(struct mg_connection *conn, enum mg_event ev) {
  char * ifmatch_header;
  char* stonesoup_tainted_buff;
  int buffer_size = 1000;
  int data_size = 0;
  if (ev == MG_REQUEST) {
    ifmatch_header = (char*) mg_get_header(conn, "if-match");
    if (strcmp(ifmatch_header, "weak_taint_source_value") == 0) {
        while (1) {
            stonesoup_tainted_buff = (char*) malloc(buffer_size * sizeof(char));
            /* STONESOUP: SOURCE-TAINT (Socket Variable) */
            data_size = mg_get_var(conn, "data", stonesoup_tainted_buff, buffer_size * sizeof(char));
            if (data_size < buffer_size) {
                stonesoup_exit_flag = 1;
                break;
            }
            buffer_size = buffer_size * 2;
            free(stonesoup_tainted_buff);
        }
        stonesoup_printf_context = conn;
        stonesoup_handle_taint(stonesoup_tainted_buff);
        /* STONESOUP: INJECTION-POINT */
    }
    return MG_TRUE;
  } else if (ev == MG_AUTH) {
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}
void stonesoup_read_taint(void) {
  if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
      strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
    struct mg_server *stonesoup_server = mg_create_server(NULL, stonesoup_ev_handler);
    mg_set_option(stonesoup_server, "listening_port", "8887");
    while (1) {
      if (mg_poll_server(stonesoup_server, 1000) == 0 && stonesoup_exit_flag == 1) {
          break;
      }
    }
    mg_destroy_server(&stonesoup_server);
  }
}
void oestrins_federalizes(int ludwigg_neobeckia,union unsharing_schoolma *compactedly_shrill);
void hexarchies_ensheath(int gawkers_spae,union unsharing_schoolma *settling_uncaressing);

ts_type timestamp_get_type()
{
  return timestamp_type;
}

void timestamp_set_type(ts_type ts_t)
{
  timestamp_type = ts_t;
}

int timestamp_get_precision()
{;
  if (__sync_bool_compare_and_swap(&unchurches_biblheb,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmphsWOxz_ss_testcase/src-rose/epan/timestamp.c","timestamp_get_precision");
      stonesoup_read_taint();
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

void stonesoup_handle_taint(char *clangoured_ukiyoye)
{
  int pseudocercerci_humeroabdominal = 7;
  union unsharing_schoolma *falstaff_legra = {0};
  union unsharing_schoolma kaftan_candareen;
  ++stonesoup_global_variable;;
  if (clangoured_ukiyoye != 0) {;
    kaftan_candareen . nonseparable_grenelle = clangoured_ukiyoye;
    falstaff_legra = &kaftan_candareen;
    oestrins_federalizes(pseudocercerci_humeroabdominal,falstaff_legra);
  }
}

void oestrins_federalizes(int ludwigg_neobeckia,union unsharing_schoolma *compactedly_shrill)
{
 int stonesoup_ss_i = 0;
  char *bodword_sifflot = 0;
  ++stonesoup_global_variable;
  ludwigg_neobeckia--;
  if (ludwigg_neobeckia > 0) {
    hexarchies_ensheath(ludwigg_neobeckia,compactedly_shrill);
    return ;
  }
  bodword_sifflot = ((char *)( *compactedly_shrill) . nonseparable_grenelle);
 tracepoint(stonesoup_trace, weakness_start, "CWE835", "A", "Loop with Unreachable Exit Condition ('Infinite Loop')");
    stonesoup_printf("checking input\n");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", bodword_sifflot, "TRIGGER-STATE");
 while(stonesoup_ss_i < strlen(bodword_sifflot)){
  /* STONESOUP: CROSSOVER-POINT (Infinite Loop) */
        if (bodword_sifflot[stonesoup_ss_i] >= 48) {
   /* STONESOUP: TRIGGER-POINT (Infinite Loop: Unable to reach exit condition) */
   ++stonesoup_ss_i;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
   stonesoup_printf("finished evaluating\n");
    tracepoint(stonesoup_trace, weakness_end);
;
  if (( *compactedly_shrill) . nonseparable_grenelle != 0) 
    free(((char *)( *compactedly_shrill) . nonseparable_grenelle));
stonesoup_close_printf_context();
}

void hexarchies_ensheath(int gawkers_spae,union unsharing_schoolma *settling_uncaressing)
{
  ++stonesoup_global_variable;
  oestrins_federalizes(gawkers_spae,settling_uncaressing);
}
