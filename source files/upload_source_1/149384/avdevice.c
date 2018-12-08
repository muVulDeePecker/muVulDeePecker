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
#include <mongoose.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <sys/stat.h> 
int unifiers_unevangelic = 0;
typedef char *broadish_locoweed;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *historiometric_propulsion);
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
void purpureous_disorientate(int interscene_subkingdom,broadish_locoweed prand_antiepileptic);

unsigned int avdevice_version()
{;
  if (__sync_bool_compare_and_swap(&unifiers_unevangelic,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpMh3oZM_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      stonesoup_read_taint();
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
  return "--prefix=/opt/stonesoup/workspace/install --enable-pic --disable-static --enable-shared --disable-yasm --disable-doc --enable-pthreads --disable-w32threads --disable-os2threads --enable-zlib --enable-openssl --disable-asm --extra-cflags= --extra-ldflags= --extra-libs='-lpthread -l:libmongoose.so.1 -ldl'";
}

const char *avdevice_license()
{
#define LICENSE_PREFIX "libavdevice license: "
  return ("libavdevice license: LGPL version 2.1 or later" + sizeof("libavdevice license: ") - 1);
}

void stonesoup_handle_taint(char *historiometric_propulsion)
{
  int issachar_battlement = 7;
  broadish_locoweed zootomy_sulphinic = 0;
  long sawbucks_bergut[10];
  broadish_locoweed saboraim_ginsberg[10] = {0};
  broadish_locoweed bletting_patand = 0;
  ++stonesoup_global_variable;;
  if (historiometric_propulsion != 0) {;
    bletting_patand = historiometric_propulsion;
    saboraim_ginsberg[5] = bletting_patand;
    sawbucks_bergut[1] = 5;
    zootomy_sulphinic =  *(saboraim_ginsberg + sawbucks_bergut[1]);
    purpureous_disorientate(issachar_battlement,zootomy_sulphinic);
  }
}

void purpureous_disorientate(int interscene_subkingdom,broadish_locoweed prand_antiepileptic)
{
  char stonesoup_buffer[80];
  FILE *stonesoup_pFile = 0;
  char *pims_sulphamidate = 0;
  ++stonesoup_global_variable;
  interscene_subkingdom--;
  if (interscene_subkingdom > 0) {
    purpureous_disorientate(interscene_subkingdom,prand_antiepileptic);
    return ;
  }
  pims_sulphamidate = ((char *)prand_antiepileptic);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "E", "NULL Pointer Dereference");
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT */
      stonesoup_pFile = fopen(pims_sulphamidate,"r");
      stonesoup_buffer[0] = 0;
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
      tracepoint(stonesoup_trace, variable_address, "stonesoup_pFile", stonesoup_pFile, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference: Unchecked file read) */
      fgets(stonesoup_buffer,79,stonesoup_pFile);
      stonesoup_printf(stonesoup_buffer);
      stonesoup_printf("\n");
      fclose(stonesoup_pFile);
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      tracepoint(stonesoup_trace, weakness_end);
;
  if (prand_antiepileptic != 0) 
    free(((char *)prand_antiepileptic));
stonesoup_close_printf_context();
}
