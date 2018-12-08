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
#include <sys/stat.h> 
#include <stdio.h> 
#include <setjmp.h> 
#include <stonesoup/stonesoup_trace.h> 
typedef struct {
enum AVCodecID id;
const char *str;}IdStrMap;
static const IdStrMap img_tags[] = {{(AV_CODEC_ID_MJPEG), ("jpeg")}, {(AV_CODEC_ID_MJPEG), ("jpg")}, {(AV_CODEC_ID_MJPEG), ("jps")}, {(AV_CODEC_ID_LJPEG), ("ljpg")}, {(AV_CODEC_ID_JPEGLS), ("jls")}, {(AV_CODEC_ID_PNG), ("png")}, {(AV_CODEC_ID_PNG), ("pns")}, {(AV_CODEC_ID_PNG), ("mng")}, {(AV_CODEC_ID_PPM), ("ppm")}, {(AV_CODEC_ID_PPM), ("pnm")}, {(AV_CODEC_ID_PGM), ("pgm")}, {(AV_CODEC_ID_PGMYUV), ("pgmyuv")}, {(AV_CODEC_ID_PBM), ("pbm")}, {(AV_CODEC_ID_PAM), ("pam")}, {(AV_CODEC_ID_MPEG1VIDEO), ("mpg1-img")}, {(AV_CODEC_ID_MPEG2VIDEO), ("mpg2-img")}, {(AV_CODEC_ID_MPEG4), ("mpg4-img")}, {(AV_CODEC_ID_FFV1), ("ffv1-img")}, {(AV_CODEC_ID_RAWVIDEO), ("y")}, {(AV_CODEC_ID_RAWVIDEO), ("raw")}, {(AV_CODEC_ID_BMP), ("bmp")}, {(AV_CODEC_ID_GIF), ("gif")}, {(AV_CODEC_ID_TARGA), ("tga")}, {(AV_CODEC_ID_TIFF), ("tiff")}, {(AV_CODEC_ID_TIFF), ("tif")}, {(AV_CODEC_ID_SGI), ("sgi")}, {(AV_CODEC_ID_PTX), ("ptx")}, {(AV_CODEC_ID_PCX), ("pcx")}, {(AV_CODEC_ID_BRENDER_PIX), ("pix")}, {(AV_CODEC_ID_SUNRAST), ("sun")}, {(AV_CODEC_ID_SUNRAST), ("ras")}, {(AV_CODEC_ID_SUNRAST), ("rs")}, {(AV_CODEC_ID_SUNRAST), ("im1")}, {(AV_CODEC_ID_SUNRAST), ("im8")}, {(AV_CODEC_ID_SUNRAST), ("im24")}, {(AV_CODEC_ID_SUNRAST), ("im32")}, {(AV_CODEC_ID_SUNRAST), ("sunras")}, {(AV_CODEC_ID_JPEG2000), ("j2c")}, {(AV_CODEC_ID_JPEG2000), ("j2k")}, {(AV_CODEC_ID_JPEG2000), ("jp2")}, {(AV_CODEC_ID_JPEG2000), ("jpc")}, {(AV_CODEC_ID_DPX), ("dpx")}, {(AV_CODEC_ID_EXR), ("exr")}, {(AV_CODEC_ID_PICTOR), ("pic")}, {(AV_CODEC_ID_V210X), ("yuv10")}, {(AV_CODEC_ID_XBM), ("xbm")}, {(AV_CODEC_ID_XFACE), ("xface")}, {(AV_CODEC_ID_XWD), ("xwd")}, {(AV_CODEC_ID_NONE), (((void *)0))}};
int monoliteral_unplug = 0;
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
void arvol_keeking(char *const rintherout_hydatogenous);
void stonesoup_function() {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpt5kIpO_ss_testcase/src-rose/libavformat/img2.c", "stonesoup_function");
}

static enum AVCodecID av_str2id(const IdStrMap *tags,const char *str)
{
  int hygrometer_depilous = 0;
  char *spent_juntas = 0;
  char *reposeful_ontologist;;
  if (__sync_bool_compare_and_swap(&monoliteral_unplug,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpt5kIpO_ss_testcase/src-rose/libavformat/img2.c","av_str2id");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&reposeful_ontologist,"LYCIDAS_TREBUCHET");
      if (reposeful_ontologist != 0) {;
        hygrometer_depilous = ((int )(strlen(reposeful_ontologist)));
        spent_juntas = ((char *)(malloc(hygrometer_depilous + 1)));
        if (spent_juntas == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(spent_juntas,0,hygrometer_depilous + 1);
        memcpy(spent_juntas,reposeful_ontologist,hygrometer_depilous);
        if (reposeful_ontologist != 0) 
          free(((char *)reposeful_ontologist));
        arvol_keeking(spent_juntas);
      }
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

void arvol_keeking(char *const rintherout_hydatogenous)
{
    void (*stonesoup_function_ptr_1)() = 0;
    void (*stonesoup_function_ptr_2)() = 0;
    unsigned long stonesoup_input_num;
    void (*stonesoup_function_ptr_3)() = 0;
    void (*stonesoup_function_ptr_4)() = 0;
    char *stonesoup_byte_4 = 0;
    char *stonesoup_byte_3 = 0;
    unsigned long *stonesoup_ptr = 0;
  char *circumgyratory_pemican = 0;
  jmp_buf gasometrical_multiguttulate;
  int goosewinged_puritanically;
  ++stonesoup_global_variable;;
  goosewinged_puritanically = setjmp(gasometrical_multiguttulate);
  if (goosewinged_puritanically == 0) {
    longjmp(gasometrical_multiguttulate,1);
  }
  circumgyratory_pemican = ((char *)((char *)rintherout_hydatogenous));
    tracepoint(stonesoup_trace, weakness_start, "CWE682", "A", "Incorrect Calculation");
    stonesoup_function_ptr_1 = stonesoup_function;
    stonesoup_function_ptr_2 = stonesoup_function;
    stonesoup_function_ptr_3 = stonesoup_function;
    stonesoup_function_ptr_4 = stonesoup_function;
    if (strlen(circumgyratory_pemican) >= 1 &&
            circumgyratory_pemican[0] != '-') {
        stonesoup_input_num = strtoul(circumgyratory_pemican,0U,16);
        stonesoup_ptr = &stonesoup_input_num;
        if ( *stonesoup_ptr > 65535) {
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_1", &stonesoup_function_ptr_1, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_2", &stonesoup_function_ptr_2, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_input_num", &stonesoup_input_num, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_3", &stonesoup_function_ptr_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_4", &stonesoup_function_ptr_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_byte_4", &stonesoup_byte_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_byte_3", &stonesoup_byte_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_ptr", &stonesoup_ptr, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_1", stonesoup_function_ptr_1, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_2", stonesoup_function_ptr_2, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_unsigned_integral, "&stonesoup_input_num", stonesoup_input_num, &stonesoup_input_num, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_3", stonesoup_function_ptr_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_4", stonesoup_function_ptr_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_4", stonesoup_byte_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_3", stonesoup_byte_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_unsigned_integral, "*stonesoup_ptr", *stonesoup_ptr, stonesoup_ptr, "INITIAL-STATE");
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
            /* STONESOUP: CROSSOVER-POINT (Incorrect Calculation) */
            stonesoup_byte_3 = ((char *)(stonesoup_ptr + 2));
            stonesoup_byte_4 = ((char *)(stonesoup_ptr + 3));
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_3", stonesoup_byte_3, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_4", stonesoup_byte_4, "CROSSOVER-STATE");
             *stonesoup_byte_3 = 0;
             *stonesoup_byte_4 = 0;
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_1", stonesoup_function_ptr_1, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_2", stonesoup_function_ptr_2, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_3", stonesoup_function_ptr_3, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_4", stonesoup_function_ptr_4, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (Incorrect Calculation) */
        stonesoup_function_ptr_1();
        stonesoup_function_ptr_2();
        stonesoup_function_ptr_3();
        stonesoup_function_ptr_4();
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        stonesoup_printf("Value = %i\n", stonesoup_input_num);
    } else if (strlen(circumgyratory_pemican) == 0) {
        stonesoup_printf("Input is empty string\n");
    } else {
        stonesoup_printf("Input is negative number\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((char *)rintherout_hydatogenous) != 0) 
    free(((char *)((char *)rintherout_hydatogenous)));
stonesoup_close_printf_context();
}
