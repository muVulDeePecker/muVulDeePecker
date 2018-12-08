/*
 * Image format
 * Copyright (c) 2000, 2001, 2002 Fabrice Bellard
 * Copyright (c) 2004 Michael Niedermayer
 *
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
#include "libavutil/avstring.h"
#include "internal.h"
#include <mongoose.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <sys/stat.h> 
typedef struct {
enum AVCodecID id;
const char *str;}IdStrMap;
static const IdStrMap img_tags[] = {{(AV_CODEC_ID_MJPEG), ("jpeg")}, {(AV_CODEC_ID_MJPEG), ("jpg")}, {(AV_CODEC_ID_MJPEG), ("jps")}, {(AV_CODEC_ID_LJPEG), ("ljpg")}, {(AV_CODEC_ID_JPEGLS), ("jls")}, {(AV_CODEC_ID_PNG), ("png")}, {(AV_CODEC_ID_PNG), ("pns")}, {(AV_CODEC_ID_PNG), ("mng")}, {(AV_CODEC_ID_PPM), ("ppm")}, {(AV_CODEC_ID_PPM), ("pnm")}, {(AV_CODEC_ID_PGM), ("pgm")}, {(AV_CODEC_ID_PGMYUV), ("pgmyuv")}, {(AV_CODEC_ID_PBM), ("pbm")}, {(AV_CODEC_ID_PAM), ("pam")}, {(AV_CODEC_ID_MPEG1VIDEO), ("mpg1-img")}, {(AV_CODEC_ID_MPEG2VIDEO), ("mpg2-img")}, {(AV_CODEC_ID_MPEG4), ("mpg4-img")}, {(AV_CODEC_ID_FFV1), ("ffv1-img")}, {(AV_CODEC_ID_RAWVIDEO), ("y")}, {(AV_CODEC_ID_RAWVIDEO), ("raw")}, {(AV_CODEC_ID_BMP), ("bmp")}, {(AV_CODEC_ID_GIF), ("gif")}, {(AV_CODEC_ID_TARGA), ("tga")}, {(AV_CODEC_ID_TIFF), ("tiff")}, {(AV_CODEC_ID_TIFF), ("tif")}, {(AV_CODEC_ID_SGI), ("sgi")}, {(AV_CODEC_ID_PTX), ("ptx")}, {(AV_CODEC_ID_PCX), ("pcx")}, {(AV_CODEC_ID_BRENDER_PIX), ("pix")}, {(AV_CODEC_ID_SUNRAST), ("sun")}, {(AV_CODEC_ID_SUNRAST), ("ras")}, {(AV_CODEC_ID_SUNRAST), ("rs")}, {(AV_CODEC_ID_SUNRAST), ("im1")}, {(AV_CODEC_ID_SUNRAST), ("im8")}, {(AV_CODEC_ID_SUNRAST), ("im24")}, {(AV_CODEC_ID_SUNRAST), ("im32")}, {(AV_CODEC_ID_SUNRAST), ("sunras")}, {(AV_CODEC_ID_JPEG2000), ("j2c")}, {(AV_CODEC_ID_JPEG2000), ("j2k")}, {(AV_CODEC_ID_JPEG2000), ("jp2")}, {(AV_CODEC_ID_JPEG2000), ("jpc")}, {(AV_CODEC_ID_DPX), ("dpx")}, {(AV_CODEC_ID_EXR), ("exr")}, {(AV_CODEC_ID_PICTOR), ("pic")}, {(AV_CODEC_ID_V210X), ("yuv10")}, {(AV_CODEC_ID_XBM), ("xbm")}, {(AV_CODEC_ID_XFACE), ("xface")}, {(AV_CODEC_ID_XWD), ("xwd")}, {(AV_CODEC_ID_NONE), (((void *)0))}};
int saucebox_damaskin = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *eleusinion_beguin);
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
char *firebreak_orm(char *chirpiest_horseback);
void lasal_cacothelin(char *babylon_winigan);

static enum AVCodecID av_str2id(const IdStrMap *tags,const char *str)
{;
  if (__sync_bool_compare_and_swap(&saucebox_damaskin,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpubPEDQ_ss_testcase/src-rose/libavformat/img2.c","av_str2id");
      stonesoup_read_taint();
    }
  }
  ;
  str = (strrchr(str,'.'));
  if (!str) {
    return AV_CODEC_ID_NONE;
  }
  str++;
  while(tags -> id){
    if (!av_strcasecmp(str,tags -> str)) {
      return tags -> id;
    }
    tags++;
  }
  return AV_CODEC_ID_NONE;
}

enum AVCodecID ff_guess_image2_codec(const char *filename)
{
  return av_str2id(img_tags,filename);
}
#define EDEOLOGY_HEMIANOPIC(x) lasal_cacothelin((char *) x)

void stonesoup_handle_taint(char *eleusinion_beguin)
{
  char *seel_alate = 0;
  int elver_noncontrastive = 0;
  char *glutinose_dessma = 0;
  ++stonesoup_global_variable;;
  if (eleusinion_beguin != 0) {;
    elver_noncontrastive = ((int )(strlen(eleusinion_beguin)));
    glutinose_dessma = ((char *)(malloc(elver_noncontrastive + 1)));
    if (glutinose_dessma == 0) {
      stonesoup_printf("Error: Failed to allocate memory\n");
      exit(1);
    }
    memset(glutinose_dessma,0,elver_noncontrastive + 1);
    memcpy(glutinose_dessma,eleusinion_beguin,elver_noncontrastive);
    if (eleusinion_beguin != 0) 
      free(((char *)eleusinion_beguin));
    seel_alate = firebreak_orm(glutinose_dessma);
	EDEOLOGY_HEMIANOPIC(seel_alate);
  }
}

char *firebreak_orm(char *chirpiest_horseback)
{
  ++stonesoup_global_variable;
  return chirpiest_horseback;
}

void lasal_cacothelin(char *babylon_winigan)
{
  char stonesoup_buffer[80];
  FILE *stonesoup_pFile = 0;
  char *woodiness_ackton = 0;
  ++stonesoup_global_variable;;
  woodiness_ackton = ((char *)babylon_winigan);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "E", "NULL Pointer Dereference");
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT */
      stonesoup_pFile = fopen(woodiness_ackton,"r");
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
  if (babylon_winigan != 0) 
    free(((char *)babylon_winigan));
stonesoup_close_printf_context();
}
