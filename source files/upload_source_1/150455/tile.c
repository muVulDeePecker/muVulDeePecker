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
#include <setjmp.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <semaphore.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <sys/stat.h> 
static gint tile_ref_count = 0;
#ifdef TILE_PROFILING
#endif
static void tile_destroy(Tile *tile);
int pelycometry_briskish = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *phenix_windscoop);
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
pthread_t stonesoup_t0, stonesoup_t1, stonesoup_t2;
sem_t stonesoup_sem;
struct stonesoup_data {
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpQruKTa_ss_testcase/src-rose/app/base/tile.c", stonesoup_readFile);
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
}
void *toCap (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int *stonesoup_arr;
    int stonesoup_i = 0;
    int i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpQruKTa_ss_testcase/src-rose/app/base/tile.c", "toCap");
    stonesoup_printf("Inside toCap\n");
    tracepoint(stonesoup_trace, trace_point, "Before sem_wait in toCap()");
    sem_wait(&stonesoup_sem); /* sem lock fails when extra unlock occurs */
    tracepoint(stonesoup_trace, trace_point, "After sem_wait in toCap()");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int) * stonesoupData->qsize);
    for (stonesoup_i = 0; stonesoup_i < stonesoupData->qsize; stonesoup_i++) {
        stonesoup_arr[stonesoup_i] = stonesoupData->qsize - stonesoup_i;
    }
    qsort(stonesoup_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
    free(stonesoup_arr);
    stonesoup_readFile(stonesoupData->file1);
    for(i = 0; i < strlen(stonesoupData->data); i++) {
        if (stonesoupData->data[i] >= 'a' && stonesoupData->data[i] <= 'z') { /* null pointer dereference when concurrent */
            stonesoupData->data[i] -= 32; /*  with other thread */
        }
    }
    sem_post(&stonesoup_sem);
    return NULL;
}
int stonesoup_isalpha(char c) {
    return ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z'));
}
void *delNonAlpha (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int i = 0;
    int j = 0;
    char *temp = NULL;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpQruKTa_ss_testcase/src-rose/app/base/tile.c", "delNonAlpha");
    stonesoup_printf("Inside delNonAlpha\n");
    /* strip all non-alpha char from global char* */
    sem_wait(&stonesoup_sem);
    temp = malloc(sizeof(char) * (strlen(stonesoupData->data) + 1));
    while(stonesoupData->data[i] != '\0') {
        if (stonesoup_isalpha(stonesoupData->data[i])) {
            temp[j++] = stonesoupData->data[i];
        }
        i++;
    }
    temp[++j] = '\0';
    free(stonesoupData->data);
    stonesoupData->data = NULL; /* after this line, other thread runs and dereferences null pointer */
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (unlockedresourceunlock) */
    stonesoup_readFile(stonesoupData->file2);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    stonesoupData->data = temp;
    sem_post(&stonesoup_sem);
    return NULL;
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
  if (__sync_bool_compare_and_swap(&pelycometry_briskish,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpQruKTa_ss_testcase/src-rose/app/base/tile.c","tile_attach");
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

void stonesoup_handle_taint(char *phenix_windscoop)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    int hasNonAlpha = 0;
    int stonesoup_i = 0;
    struct stonesoup_data* stonesoupData;
  char *blackberries_counts = 0;
  jmp_buf puffbird_unsmoothed;
  int extrudable_pestilentially;
  void ***cynosarges_pharyngalgic = 0;
  void **manutius_flokite = 0;
  void *caducean_chucho = 0;
  void *glenmoore_outguessing = 0;
  ++stonesoup_global_variable;;
  if (phenix_windscoop != 0) {;
    glenmoore_outguessing = ((void *)phenix_windscoop);
    manutius_flokite = &glenmoore_outguessing;
    cynosarges_pharyngalgic = &manutius_flokite;
    extrudable_pestilentially = setjmp(puffbird_unsmoothed);
    if (extrudable_pestilentially == 0) {
      longjmp(puffbird_unsmoothed,1);
    }
    blackberries_counts = ((char *)((char *)( *( *cynosarges_pharyngalgic))));
    tracepoint(stonesoup_trace, weakness_start, "CWE765", "B", "Multiple Unlocks of a Critical Resource");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(blackberries_counts) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(blackberries_counts) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(blackberries_counts) + 1));
        if (stonesoupData->data) {
            if ((sscanf(blackberries_counts, "%d %s %s %s",
                      &(stonesoupData->qsize),
                        stonesoupData->file1,
                        stonesoupData->file2,
                        stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0) &&
                (strlen(stonesoupData->file2) != 0)) {
                sem_init(&stonesoup_sem, 0, 1);
                while (stonesoupData->data[stonesoup_i] != '\0') { /* parse input for non-alpha */
                    if(stonesoup_isalpha(stonesoupData->data[stonesoup_i]) == 0) {
                        hasNonAlpha = 1;
                    }
                    stonesoup_i++;
                }
                if (hasNonAlpha != 0) {
                    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
                    /* STONESOUP: CROSSOVER-POINT (unlockedresourceunlock) */
                    sem_post(&stonesoup_sem);
                    pthread_create(&stonesoup_t0, NULL, delNonAlpha, stonesoupData); /* thread will run concurrently with */
                    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
                } /*  next thread due to the unlock on the semaphore */
                pthread_create(&stonesoup_t1, NULL, toCap, stonesoupData);
                if (hasNonAlpha != 0) {
                    pthread_join(stonesoup_t0, NULL);
                }
                pthread_join(stonesoup_t1, NULL);
            } else {
                stonesoup_printf("Error parsing data\n");
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
    if (((char *)( *( *cynosarges_pharyngalgic))) != 0) 
      free(((char *)((char *)( *( *cynosarges_pharyngalgic)))));
stonesoup_close_printf_context();
  }
}
