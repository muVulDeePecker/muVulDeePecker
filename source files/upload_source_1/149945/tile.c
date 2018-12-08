/* GIMP - The GNU Image Manipulation Program
 * Copyright (C) 1995 Spencer Kimball and Peter Mattis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"
#include <glib-object.h>
#include "base-types.h"
#include "tile.h"
#include "tile-cache.h"
#include "tile-manager.h"
#include "tile-rowhints.h"
#include "tile-swap.h"
#include "tile-private.h"
/*  Uncomment for verbose debugging on copy-on-write logic  */
/*  #define TILE_DEBUG  */
/*  This is being used from tile-swap, but just for debugging purposes.  */
#include <mongoose.h> 
#include <string.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <sys/stat.h> 
#include <unistd.h> 
static gint tile_ref_count = 0;
#ifdef TILE_PROFILING
#endif
static void tile_destroy(Tile *tile);
int retouchers_formolit = 0;

union misestimating_bradawls 
{
  char *vassalless_spoiler;
  double remilitarize_rouvin;
  char *paulite_ungratification;
  char levine_unintimidated;
  int unrotatory_virous;
}
;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *moonery_teadish);
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
int stonesoup_comp (const void * a, const void * b)
{
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
int stonesoup_pmoc (const void * a, const void * b)
{
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0N792h_ss_testcase/src-rose/app/base/tile.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading from sync file.");
}
void waitForChange(char* file, char* sleepFile) {
    int fd;
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0N792h_ss_testcase/src-rose/app/base/tile.c", "stonesoup_waitForChange");
    stonesoup_printf("In waitForChange\n");
    strcat(filename, file);
    strcat(filename, ".pid");
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error writing to file.");
            stonesoup_printf("Error writing to file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Wrote .pid file.");
        if (close(fd) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error closing file.");
            stonesoup_printf("Error closing file.");
        }
        stonesoup_readFile(sleepFile);
    }
}
int stonesoup_is_valid(char *path)
{
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0N792h_ss_testcase/src-rose/app/base/tile.c", "stonesoup_is_valid");
    if(access(path, F_OK) != -1) {
        tracepoint(stonesoup_trace, trace_point, "Path is accessible");
        stonesoup_printf("Path is accessible\n");
        return 1;
    }
    tracepoint(stonesoup_trace, trace_point, "Path is not accessible");
    stonesoup_printf("Path is not accessible\n");
    return 0;
}
int stonesoup_path_is_relative(char *path) {
    char *chr = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0N792h_ss_testcase/src-rose/app/base/tile.c", "stonesoup_path_is_relative");
    chr = strchr(path,'/');
    if (chr == 0) {
        stonesoup_printf("Path is relative\n");
        return 1;
    } else {
        stonesoup_printf("Path is not relative\n");
        return 0;
    }
}
char * stonesoup_get_absolute_path(char * path) {
    char * abs_path = malloc (sizeof(char) * (strlen("/opt/stonesoup/workspace/testData/") * strlen(path) + 1));
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0N792h_ss_testcase/src-rose/app/base/tile.c", "stonesoup_get_absolute_path");
    if (abs_path == NULL) {
        tracepoint(stonesoup_trace, trace_error, "Cannot allocate memory for path");
        stonesoup_printf("Cannot allocate memory for path\n");
    } else {
        stonesoup_printf("Creating absolute path\n");
        strcpy(abs_path, "/opt/stonesoup/workspace/testData/");
        tracepoint(stonesoup_trace, variable_buffer, "abs_path", abs_path, "Generated absolute path");
        strcat(abs_path, path);
    }
    return abs_path;
}

Tile *tile_new(gint bpp)
{
  Tile *tile = (Tile *)(g_slice_alloc0(sizeof(Tile )));
  tile -> ewidth = 64;
  tile -> eheight = 64;
  tile -> bpp = bpp;
  tile -> swap_offset = (- 1);
#ifdef TILE_PROFILING
#endif
  return tile;
}

void tile_lock(Tile *tile)
{
/* Increment the global reference count.
   */
  tile_ref_count++;
/* Increment this tile's reference count.
   */
  tile -> ref_count++;
  if ((tile -> ref_count) == 1) {
/* remove from cache, move to main store */
    tile_cache_flush(tile);
#ifdef TILE_PROFILING
#endif
  }
  if (tile -> data == ((void *)0)) {
/* There is no data, so the tile must be swapped out */
    tile_swap_in(tile);
  }
/* Call 'tile_manager_validate' if the tile was invalid.
   */
  if (!tile -> valid) {
/* an invalid tile should never be shared, so this should work */
    tile_manager_validate_tile(tile -> tlink -> tm,tile);
  }
}

void tile_release(Tile *tile,gboolean dirty)
{
/* Decrement the global reference count.
   */
  tile_ref_count--;
/* Decrement this tile's reference count.
   */
  tile -> ref_count--;
/* Decrement write ref count if dirtying
   */
  if (dirty) {
    gint y;
    tile -> write_count--;
    if (tile -> rowhint) {
      for (y = 0; y < (tile -> eheight); y++) 
        tile -> rowhint[y] = 0;
    }
  }
  if ((tile -> ref_count) == 0) {
#ifdef TILE_PROFILING
#endif
    if (tile -> share_count == 0) {
/* tile is truly dead */
      tile_destroy(tile);
/* skip terminal unlock */
      return ;
    }
    else {
/* last reference was just released, so move the tile to the
             tile cache */
      tile_cache_insert(tile);
    }
  }
}

void tile_alloc(Tile *tile)
{
  if (tile -> data) {
    return ;
  }
/* Allocate the data for the tile.
   */
  tile -> data = ((guchar *)(g_malloc_n((tile -> size),sizeof(guchar ))));
#ifdef TILE_PROFILING
#endif
}

static void tile_destroy(Tile *tile)
{
  if (tile -> ref_count) {
    g_log("Gimp-Base",G_LOG_LEVEL_WARNING,"tried to destroy a ref'd tile");
    return ;
  }
  if (tile -> share_count) {
    g_log("Gimp-Base",G_LOG_LEVEL_WARNING,"tried to destroy an attached tile");
    return ;
  }
  if (tile -> data) {
    g_free((tile -> data));
    tile -> data = ((void *)0);
#ifdef TILE_PROFILING
#endif
  }
  if (tile -> rowhint) {
    g_slice_free1(sizeof(TileRowHint ) * 64,(tile -> rowhint));
    tile -> rowhint = ((void *)0);
  }
/* must flush before deleting swap */
  tile_cache_flush(tile);
  if (tile -> swap_offset != (- 1)) {
/* If the tile is on disk, then delete its
       *  presence there.
       */
    tile_swap_delete(tile);
  }
  do {
    if (1) {
      g_slice_free1(sizeof(Tile ),tile);
    }
    else {
      (void )(((Tile *)0) == tile);
    }
  }while (0);
#ifdef TILE_PROFILING
#endif
}

gint tile_size(Tile *tile)
{
/* Return the actual size of the tile data.
   *  (Based on its effective width and height).
   */
  return tile -> size;
}

gint tile_ewidth(Tile *tile)
{
  return (tile -> ewidth);
}

gint tile_eheight(Tile *tile)
{
  return (tile -> eheight);
}

gint tile_bpp(Tile *tile)
{
  return (tile -> bpp);
}

gboolean tile_is_valid(Tile *tile)
{
  return (tile -> valid);
}

void tile_attach(Tile *tile,void *tm,gint tile_num)
{
  TileLink *new;
  if (__sync_bool_compare_and_swap(&retouchers_formolit,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp0N792h_ss_testcase/src-rose/app/base/tile.c","tile_attach");
      stonesoup_read_taint();
    }
  }
  if (tile -> share_count > 0 && !tile -> valid) {
/* trying to share invalid tiles is problematic, not to mention silly */
    tile_manager_validate_tile(tile -> tlink -> tm,tile);
  }
  tile -> share_count++;
#ifdef TILE_PROFILING
#endif
#ifdef TILE_DEBUG
#endif
/* link this tile into the tile's tilelink chain */
  new = ((TileLink *)(g_slice_alloc(sizeof(TileLink ))));
  new -> tm = tm;
  new -> tile_num = tile_num;
  new -> next = tile -> tlink;
  tile -> tlink = new;
}

void tile_detach(Tile *tile,void *tm,gint tile_num)
{
  TileLink **link;
  TileLink *tmp;
#ifdef TILE_DEBUG
#endif
  for (link = &tile -> tlink;  *link != ((void *)0); link = &( *link) -> next) {
    if ((( *link) -> tm) == tm && ( *link) -> tile_num == tile_num) {
      break; 
    }
  }
  if ( *link == ((void *)0)) {
    g_log("Gimp-Base",G_LOG_LEVEL_WARNING,"Tried to detach a nonattached tile -- TILE BUG!");
    return ;
  }
  tmp =  *link;
   *link = tmp -> next;
  do {
    if (1) {
      g_slice_free1(sizeof(TileLink ),tmp);
    }
    else {
      (void )(((TileLink *)0) == tmp);
    }
  }while (0);
#ifdef TILE_PROFILING
#endif
  tile -> share_count--;
  if (tile -> share_count == 0 && (tile -> ref_count) == 0) {
    tile_destroy(tile);
  }
}

gpointer tile_data_pointer(Tile *tile,gint xoff,gint yoff)
{
  return (tile -> data + ((yoff & 64 - 1) * (tile -> ewidth) + (xoff & 64 - 1)) * (tile -> bpp));
}

gint tile_global_refcount()
{
  return tile_ref_count;
}

void stonesoup_handle_taint(char *moonery_teadish)
{
    int stonesoup_size = 0;
    FILE *stonesoup_file = 0;
    char *stonesoup_buffer = 0;
    char *stonesoup_str = 0;
    char *stonesoup_abs_path = 0;
    char *stonesoup_sleep_file = 0;
  char *scamell_lepta = 0;
  union misestimating_bradawls tackingly_iskenderun = {0};
  int *microphonic_pfeffernuss = 0;
  int agapanthus_pennatulidae;
  union misestimating_bradawls nelson_harmonici[10] = {0};
  union misestimating_bradawls logisticians_vernalised;
  ++stonesoup_global_variable;;
  if (moonery_teadish != 0) {;
    logisticians_vernalised . vassalless_spoiler = moonery_teadish;
    nelson_harmonici[5] = logisticians_vernalised;
    agapanthus_pennatulidae = 5;
    microphonic_pfeffernuss = &agapanthus_pennatulidae;
    tackingly_iskenderun =  *(nelson_harmonici +  *microphonic_pfeffernuss);
    scamell_lepta = ((char *)tackingly_iskenderun . vassalless_spoiler);
    tracepoint(stonesoup_trace, weakness_start, "CWE367", "A", "Time of Check Time of Use Race Condition");
    stonesoup_str = malloc(sizeof(char) * (strlen(scamell_lepta) + 1));
    stonesoup_sleep_file = malloc(sizeof(char) * (strlen(scamell_lepta) + 1));
    if (stonesoup_str != NULL && stonesoup_sleep_file != NULL &&
        (sscanf(scamell_lepta, "%s %s",
                stonesoup_sleep_file,
                stonesoup_str) == 2) &&
        (strlen(stonesoup_str) != 0) &&
        (strlen(stonesoup_sleep_file) != 0))
    {
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_sleep_file", stonesoup_sleep_file, "INITIAL-STATE");
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_str", stonesoup_str, "INITIAL-STATE");
        if (stonesoup_path_is_relative(stonesoup_str)) {
            stonesoup_abs_path = stonesoup_get_absolute_path(stonesoup_str);
            if (stonesoup_abs_path != NULL) {
               if (stonesoup_is_valid(stonesoup_abs_path)) {
                  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
                    /* STONESOUP: CROSSOVER-POINT (Time of Check, Time of Use) */
                    waitForChange(stonesoup_abs_path, stonesoup_sleep_file);
                   tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
                   tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
                    /* STONESOUP: TRIGGER-POINT (Time of Check, Time of Use) */
                    stonesoup_file = fopen(stonesoup_abs_path,"rb");
                    fseek(stonesoup_file,0,2);
                    stonesoup_size = ftell(stonesoup_file);
                    rewind(stonesoup_file);
                    stonesoup_buffer = ((char *)(malloc(sizeof(char ) * (stonesoup_size + 1))));
                    if (stonesoup_buffer != NULL) {
                        fread(stonesoup_buffer,sizeof(char ),stonesoup_size,stonesoup_file);
                        stonesoup_buffer[stonesoup_size] = '\0';
                        stonesoup_printf(stonesoup_buffer);
                        free(stonesoup_buffer);
                    }
                   tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
                    fclose(stonesoup_file);
                }
            }
            free(stonesoup_abs_path);
        }
        free(stonesoup_str);
    } else {
       tracepoint(stonesoup_trace, trace_error, "Error parsing input");
        stonesoup_printf("Error parsing input.\n");
    }
;
    if (tackingly_iskenderun . vassalless_spoiler != 0) 
      free(((char *)tackingly_iskenderun . vassalless_spoiler));
stonesoup_close_printf_context();
  }
}
