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
#include <stdio.h> 
#include <stdlib.h> 
#include <sys/stat.h> 
static gint tile_ref_count = 0;
#ifdef TILE_PROFILING
#endif
static void tile_destroy(Tile *tile);
int christhood_renderings = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *tormae_vitaceous);
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
void bruceton_phoronomy(void *const greaseball_landslidden);
void tetramorph_omagra(void *belgravia_unadmirableness);
struct stonesoup_struct_data {
  char *buffer_member;
  unsigned short size_member;
};
struct stonesoup_struct_data *stonesoup_init_data(long number_param)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmp0lsoE1_ss_testcase/src-rose/app/base/tile.c", "stonesoup_init_data");
  struct stonesoup_struct_data *init_data_ptr = 0;
  init_data_ptr = ((struct stonesoup_struct_data *)(malloc(sizeof(struct stonesoup_struct_data ))));
  if (init_data_ptr == 0)
    return 0;
  init_data_ptr -> size_member = 0;
  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Numerical Truncation Error) */
  init_data_ptr -> size_member = number_param;
  init_data_ptr -> buffer_member = ((char *)(malloc(sizeof(char ) * init_data_ptr -> size_member)));
  tracepoint(stonesoup_trace, variable_signed_integral, "number_param", number_param, &number_param, "CROSSOVER-STATE");
  tracepoint(stonesoup_trace, variable_signed_integral, "(init_data_ptr->size_member)", (init_data_ptr->size_member), &(init_data_ptr->size_member), "CROSSOVER-STATE");
  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
  if (init_data_ptr -> buffer_member == 0) {
    free(init_data_ptr);
    return 0;
  }
  memset(init_data_ptr -> buffer_member,'a',init_data_ptr -> size_member);
  init_data_ptr -> buffer_member[init_data_ptr -> size_member - 1] = 0;
  return init_data_ptr;
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
  if (__sync_bool_compare_and_swap(&christhood_renderings,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp0lsoE1_ss_testcase/src-rose/app/base/tile.c","tile_attach");
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

void stonesoup_handle_taint(char *tormae_vitaceous)
{
  void *voltaire_tannish = 0;
  ++stonesoup_global_variable;;
  if (tormae_vitaceous != 0) {;
    voltaire_tannish = ((void *)tormae_vitaceous);
    bruceton_phoronomy(voltaire_tannish);
  }
}

void bruceton_phoronomy(void *const greaseball_landslidden)
{
  ++stonesoup_global_variable;;
  tetramorph_omagra(greaseball_landslidden);
}

void tetramorph_omagra(void *belgravia_unadmirableness)
{
    long stonesoup_number;
    struct stonesoup_struct_data *stonesoup_data = 0;
  char *ruckle_fonnish = 0;
  ++stonesoup_global_variable;;
  ruckle_fonnish = ((char *)((char *)((void *)belgravia_unadmirableness)));
    tracepoint(stonesoup_trace, weakness_start, "CWE197", "A", "Numeric Truncation Error");
    stonesoup_number = strtol(ruckle_fonnish,0U,10);
    if (stonesoup_number > 0) {
        stonesoup_data = stonesoup_init_data(stonesoup_number);
        if (stonesoup_data != 0) {
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Numerical Truncation Error) */
          memset(stonesoup_data -> buffer_member, 98, stonesoup_number);
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
          stonesoup_data -> buffer_member[stonesoup_number - 1] = 0;
          stonesoup_printf("%s\n", stonesoup_data -> buffer_member);
          if (stonesoup_data -> buffer_member != 0U)
            free(stonesoup_data -> buffer_member);
          if (stonesoup_data != 0U)
            free(stonesoup_data);
        }
    } else {
        stonesoup_printf("Input is less than or equal to 0\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((char *)((void *)belgravia_unadmirableness)) != 0) 
    free(((char *)((char *)((void *)belgravia_unadmirableness))));
stonesoup_close_printf_context();
}
