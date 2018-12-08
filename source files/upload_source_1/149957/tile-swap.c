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
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <glib-object.h>
#include <glib/gstdio.h>
#include "libgimpbase/gimpbase.h"
#include "libgimpconfig/gimpconfig.h"
#ifdef G_OS_WIN32
#include <windows.h>
#include "libgimpbase/gimpwin32-io.h"
#endif
#include "base-types.h"
#ifndef _O_BINARY
#define _O_BINARY 0
#endif
#ifndef _O_TEMPORARY
#define _O_TEMPORARY 0
#endif
#include "base-utils.h"
#include "tile.h"
#include "tile-rowhints.h"
#include "tile-swap.h"
#include "tile-private.h"
#include "tile-cache.h"
#include "gimp-intl.h"
#include <mongoose.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <stdlib.h> 
typedef enum __anonymous_0x32556a0 {SWAP_IN=1,SWAP_OUT=2,SWAP_DELETE=3}SwapCommand;
typedef gint (*SwapFunc)(gint , Tile *, SwapCommand );
#define MAX_OPEN_SWAP_FILES  16
struct _SwapFile ;
typedef struct _SwapFile SwapFile;
struct _SwapFileGap ;
typedef struct _SwapFileGap SwapFileGap;

struct _SwapFile 
{
  gchar *filename;
  gint fd;
  GList *gaps;
  gint64 swap_file_end;
  gint64 cur_position;
}
;

struct _SwapFileGap 
{
  gint64 start;
  gint64 end;
}
;
static void tile_swap_command(Tile *tile,gint command);
static void tile_swap_default_in(SwapFile *swap_file,Tile *tile);
static void tile_swap_default_out(SwapFile *swap_file,Tile *tile);
static void tile_swap_default_delete(SwapFile *swap_file,Tile *tile);
static gint64 tile_swap_find_offset(SwapFile *swap_file,gint64 bytes);
static void tile_swap_open(SwapFile *swap_file);
static void tile_swap_resize(SwapFile *swap_file,gint64 new_size);
static SwapFileGap *tile_swap_gap_new(gint64 start,gint64 end);
static void tile_swap_gap_destroy(SwapFileGap *gap);
static SwapFile *gimp_swap_file = ((void *)0);
static const guint64 swap_file_grow = (1024 * 64 * 64 * 4);
static gboolean seek_err_msg = !0;
static gboolean read_err_msg = !0;
static gboolean write_err_msg = !0;
#ifdef TILE_PROFILING
/* how many tiles were swapped out under cache pressure but never
   swapped back in?  This does not count idle swapped tiles, as those
   do not contribute to any perceived load or latency */
/* total tile flushes under cache pressure */
/* total tiles swapped out to swap file (not total calls to swap out;
   this only counts actual flushes to disk) */
/* total tiles swapped in from swap file (not total calls to swap in;
   this only counts actual tile reads from disk) */
/* total dead time spent waiting to read or write */
/* total time spent in tile cache due to cache pressure */
#endif
#ifdef G_OS_WIN32
#define LARGE_SEEK(f, o, w) _lseeki64 (f, o, w)
#define LARGE_TRUNCATE(f, s) win32_large_truncate (f, s)
#else
#define LARGE_SEEK(f, o, t) lseek (f, o, t)
#define LARGE_TRUNCATE(f, s) ftruncate (f, s)
#endif
#ifdef GIMP_UNSTABLE
#endif
int dioptry_devow = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *thermotaxis_diagonal);
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
void melaena_gooseweed(char **hiller_dunnville);
void prankiest_harwood(char **huesca_fanciness);
void uteropexy_tiemaking(char **nevins_knolling);
void gybed_cracksman(char **sergias_herodian);
void homotaxial_ira(char **unpushed_diplococcus);
void trainings_algesimeter(char **furrily_uneddying);
void rhematology_kenos(char **fashiousness_designatum);
void richthofen_desperate(char **nonsegmentally_stankie);
void abscess_preinterview(char **prioritizes_swashingly);
void tamburitza_nononerously(char **partisanship_phaeophyta);
void scarn_ensnarls(char **mimicker_gulper);
void splanchnography_admi(char **meteor_canaut);
void inweaving_tromometry(char **greycoat_heliotropic);
void intersituating_supralateral(char **hypaesthesia_personam);
void dodecaphonism_unadulteration(char **stereoed_pleuropneumonic);
void felicitate_agkistrodon(char **caboose_superinduction);
void lutesville_pemmicanization(char **ridgling_compactest);
void immaterials_guamuchil(char **centimes_beqwete);
void buckstone_canacuas(char **hadith_gattine);
void greeshoch_amfortas(char **smallboy_triode);
void amygdalae_huave(char **nerine_repure);
void earwort_reentering(char **hearselike_hogshouther);
void rudd_euchres(char **hoping_leisureless);
void billiton_bathymetrically(char **fructuate_reinitiate);
void altesse_jowars(char **dicumarol_preexperience);
void trull_scrubber(char **shank_gormandiser);
void unmodifiably_remanie(char **sadducee_chirologist);
void rep_penaeaceous(char **bem_furnacite);
void untaking_skagerrak(char **catchie_brimstone);
void craftsbury_wetsuit(char **riemannean_fatma);
void matures_agoranome(char **cathion_geulincx);
void semicomplicated_valenay(char **paramountship_drugmaker);
void preemptor_sakkos(char **multangulum_verbalised);
void reproaches_unabsorbingly(char **orate_hypoergic);
void breakwaters_taharah(char **procreant_ranger);
void yamshik_jen(char **thuggism_adf);
void colubaria_atavic(char **coruscative_understratum);
void sark_madeline(char **nazifies_underbeam);
void superpro_genioglossi(char **oursels_truest);
void overspiced_journeyman(char **frankforters_blephillia);
void arcadianism_divergency(char **anend_predeparture);
void nonmoveably_laneville(char **pentite_waywort);
void rearmost_antistimulant(char **shrinking_waterishness);
void edf_arboriculture(char **queens_rion);
void puelchean_eggplant(char **chinoidine_dodonean);
void hemiparaplegia_wiredraw(char **cotypes_atb);
void epaphus_disavowed(char **trichi_squarier);
void iztaccihuatl_spancel(char **gurnee_eperua);
void silvexes_rather(char **swallowpipe_coyoting);
void hydatina_attrib(char **customariness_sulfonating);
struct stonesoup_data {
    int inc_amount;
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
int stonesoup_comp (const void * a, const void * b) {
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
int stonesoup_pmoc (const void * a, const void * b) {
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmprRRrcJ_ss_testcase/src-rose/app/base/tile-swap.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void *calcIncamount(void *data) {
    struct stonesoup_data *dataStruct = (struct stonesoup_data*)data;
    stonesoup_printf("In calcInamount\n");
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmprRRrcJ_ss_testcase/src-rose/app/base/tile-swap.c", "calcIncamount");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    /* STONESOUP: CROSSOVER-POINT (missing syncronization) */
    dataStruct->inc_amount = dataStruct->data[0] - 'A'; /* oops...um... */
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "CROSSOVER-STATE");
    stonesoup_readFile(dataStruct->file2);
    if (dataStruct->inc_amount < 0) { /* let's just clean up and */
        dataStruct->inc_amount *= -1; /*  pretend that never happened */
    }
    else if (dataStruct->inc_amount == 0) { /*  shhhh */
        dataStruct->inc_amount += 1;
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "FINAL-STATE");
    return NULL;
}
void *toPound(void *data) {
    int stonesoup_i;
    struct stonesoup_data *dataStruct = (struct stonesoup_data*)data;
    int *stonesoup_arr = NULL;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmprRRrcJ_ss_testcase/src-rose/app/base/tile-swap.c", "toPound");
    stonesoup_printf("In toPound\n");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int) * dataStruct->qsize);
    for (stonesoup_i = 0; stonesoup_i < dataStruct->qsize; stonesoup_i++) {
        stonesoup_arr[stonesoup_i] = dataStruct->qsize - stonesoup_i;
    }
    qsort(stonesoup_arr, dataStruct->qsize, sizeof(int), &stonesoup_comp);
    free(stonesoup_arr);
    stonesoup_readFile(dataStruct->file1);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "TRIGGER-STATE");
    /* STONESOUP: TRIGGER-POINT (missing syncronization) */
    for (stonesoup_i = 0; stonesoup_i < (int)strlen(dataStruct->data) - 1;
         stonesoup_i += dataStruct->inc_amount) /* can cause underread/write if */
    {
        dataStruct->data[stonesoup_i] = '#'; /* stonesoup_increment_amount is neg */
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    return NULL;
}

void tile_swap_init(const gchar *path)
{
  gchar *basename;
  gchar *dirname;
  do {
    if (gimp_swap_file == ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Base",__PRETTY_FUNCTION__,"gimp_swap_file == NULL");
      return ;
    }
    ;
  }while (0);
  do {
    if (path != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Base",__PRETTY_FUNCTION__,"path != NULL");
      return ;
    }
    ;
  }while (0);
  dirname = gimp_config_path_expand(path,!0,((void *)0));
  basename = g_strdup_printf("gimpswap.%lu",((unsigned long )(get_pid())));
/*  create the swap directory if it doesn't exist */
  if (!g_file_test(dirname,G_FILE_TEST_EXISTS)) {
    g_mkdir_with_parents(dirname,0400 | 0100 | 0200 | 0400 >> 3 | 0100 >> 3 | 0400 >> 3 >> 3 | 0100 >> 3 >> 3);
  }
  gimp_swap_file = ((SwapFile *)(g_slice_alloc(sizeof(SwapFile ))));
  gimp_swap_file -> filename = g_build_filename(dirname,basename,((void *)0));
  gimp_swap_file -> gaps = ((void *)0);
  gimp_swap_file -> swap_file_end = 0;
  gimp_swap_file -> cur_position = 0;
  gimp_swap_file -> fd = - 1;
  g_free(basename);
  g_free(dirname);
}

void tile_swap_exit()
{
#ifdef TILE_PROFILING
#endif
  if (tile_global_refcount() != 0) {
    g_log("Gimp-Base",G_LOG_LEVEL_WARNING,"tile ref count balance: %d\n",tile_global_refcount());
  }
  do {
    if (gimp_swap_file != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Base",__PRETTY_FUNCTION__,"gimp_swap_file != NULL");
      return ;
    }
    ;
  }while (0);
#ifdef GIMP_UNSTABLE
#endif
#ifdef G_OS_WIN32
/* should close before unlink */
#endif
  g_unlink((gimp_swap_file -> filename));
  g_free((gimp_swap_file -> filename));
  do {
    if (1) {
      g_slice_free1(sizeof(SwapFile ),gimp_swap_file);
    }
    else {
      (void )(((SwapFile *)0) == gimp_swap_file);
    }
  }while (0);
  gimp_swap_file = ((void *)0);
}
/* check if we can open a swap file */

gboolean tile_swap_test()
{
  do {
    if (gimp_swap_file != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Base",__PRETTY_FUNCTION__,"gimp_swap_file != NULL");
      return 0;
    }
    ;
  }while (0);
/* make sure this duplicates the open() call from tile_swap_open() */
  gimp_swap_file -> fd = open((gimp_swap_file -> filename),0100 | 02 | 0 | 0,0400 | 0200);
  if (gimp_swap_file -> fd != - 1) {
    close(gimp_swap_file -> fd);
    gimp_swap_file -> fd = - 1;
    g_unlink((gimp_swap_file -> filename));
    return !0;
  }
  return 0;
}

void tile_swap_in(Tile *tile)
{
  if (tile -> swap_offset == (- 1)) {
    tile_alloc(tile);
    return ;
  }
  tile_swap_command(tile,SWAP_IN);
}

void tile_swap_out(Tile *tile)
{
  tile_swap_command(tile,SWAP_OUT);
}

void tile_swap_delete(Tile *tile)
{
  tile_swap_command(tile,SWAP_DELETE);
}

static void tile_swap_command(Tile *tile,gint command)
{
  if (gimp_swap_file -> fd == - 1) {
    tile_swap_open(gimp_swap_file);
    if (gimp_swap_file -> fd == - 1) {
      return ;
    }
  }
  switch(command){
    case SWAP_IN:
{
      tile_swap_default_in(gimp_swap_file,tile);
      break; 
    }
    case SWAP_OUT:
{
      tile_swap_default_out(gimp_swap_file,tile);
      break; 
    }
    case SWAP_DELETE:
{
      tile_swap_default_delete(gimp_swap_file,tile);
      break; 
    }
  }
}
/* The actual swap file code. The swap file consists of tiles
 *  which have been moved out to disk in order to conserve memory.
 *  The swap file format is free form. Any tile in memory may
 *  end up anywhere on disk.
 * An actual tile in the swap file consists only of the tile data.
 *  The offset of the tile on disk is stored in the tile data structure
 *  in memory.
 */

static void tile_swap_default_in(SwapFile *swap_file,Tile *tile)
{
  gint nleft;
  gint64 offset;
#ifdef TILE_PROFILING
#endif
  if (tile -> data) {
    return ;
  }
  tile_cache_suspend_idle_swapper();
#ifdef TILE_PROFILING
#endif
  if (swap_file -> cur_position != tile -> swap_offset) {
    swap_file -> cur_position = tile -> swap_offset;
#ifdef TILE_PROFILING
#endif
    offset = lseek(swap_file -> fd,tile -> swap_offset,0);
    if (offset == (- 1)) {
      if (seek_err_msg) {
        g_log("Gimp-Base",G_LOG_LEVEL_MESSAGE,"unable to seek to tile location on disk: %s",g_strerror( *__errno_location()));
      }
      seek_err_msg = 0;
      return ;
    }
  }
  tile_alloc(tile);
  nleft = tile -> size;
  while(nleft > 0){
    gint err;
    do {
      err = (read(swap_file -> fd,(tile -> data + tile -> size - nleft),nleft));
    }while (err == - 1 && ( *__errno_location() == 11 ||  *__errno_location() == 4));
    if (err <= 0) {
      if (read_err_msg) {
        g_log("Gimp-Base",G_LOG_LEVEL_MESSAGE,"unable to read tile data from disk: %s (%d/%d bytes read)",g_strerror( *__errno_location()),err,nleft);
      }
      read_err_msg = 0;
      return ;
    }
    nleft -= err;
  }
#ifdef TILE_PROFILING
#endif
  swap_file -> cur_position += (tile -> size);
/*  Do not delete the swap from the file  */
/*  tile_swap_default_delete (swap_file, fd, tile);  */
  read_err_msg = seek_err_msg = !0;
}

static void tile_swap_default_out(SwapFile *swap_file,Tile *tile)
{
  gint bytes;
  gint nleft;
  gint64 offset;
  gint64 newpos;
#ifdef TILE_PROFILING
#endif
  bytes = 64 * 64 * (tile -> bpp);
/*  If there is already a valid swap_offset, use it  */
  if (tile -> swap_offset == (- 1)) {
    newpos = tile_swap_find_offset(swap_file,bytes);
  }
  else {
    newpos = tile -> swap_offset;
  }
  if (swap_file -> cur_position != newpos) {
#ifdef TILE_PROFILING
#endif
    offset = lseek(swap_file -> fd,newpos,0);
    if (offset == (- 1)) {
      if (seek_err_msg) {
        g_log("Gimp-Base",G_LOG_LEVEL_MESSAGE,"unable to seek to tile location on disk: %s",g_strerror( *__errno_location()));
      }
      seek_err_msg = 0;
      return ;
    }
    swap_file -> cur_position = newpos;
  }
  nleft = tile -> size;
  while(nleft > 0){
    gint err = (write(swap_file -> fd,(tile -> data + tile -> size - nleft),nleft));
    if (err <= 0) {
      if (write_err_msg) {
        g_log("Gimp-Base",G_LOG_LEVEL_MESSAGE,"unable to write tile data to disk: %s (%d/%d bytes written)",g_strerror( *__errno_location()),err,nleft);
      }
      write_err_msg = 0;
      return ;
    }
    nleft -= err;
  }
#ifdef TILE_PROFILING
#endif
  swap_file -> cur_position += (tile -> size);
/* Do NOT free tile->data because we may be pre-swapping.
   * tile->data is freed in tile_cache_zorch_next
   */
  tile -> dirty = 0;
  tile -> swap_offset = newpos;
  write_err_msg = seek_err_msg = !0;
}

static void tile_swap_default_delete(SwapFile *swap_file,Tile *tile)
{
  SwapFileGap *gap;
  SwapFileGap *gap2;
  GList *tmp;
  GList *tmp2;
  gint64 start;
  gint64 end;
  if (tile -> swap_offset == (- 1)) {
    return ;
  }
#ifdef TILE_PROFILING
#endif
  start = tile -> swap_offset;
  end = start + (64 * 64 * (tile -> bpp));
  tile -> swap_offset = (- 1);
  tmp = swap_file -> gaps;
  while(tmp){
    gap = (tmp -> data);
    if (end == gap -> start) {
      gap -> start = start;
      if (tmp -> prev) {
        gap2 = (tmp -> prev -> data);
        if (gap -> start == gap2 -> end) {
          gap2 -> end = gap -> end;
          tile_swap_gap_destroy(gap);
          swap_file -> gaps = g_list_remove_link(swap_file -> gaps,tmp);
          g_list_free(tmp);
        }
      }
      break; 
    }
    else {
      if (start == gap -> end) {
        gap -> end = end;
        if (tmp -> next) {
          gap2 = (tmp -> next -> data);
          if (gap -> end == gap2 -> start) {
            gap2 -> start = gap -> start;
            tile_swap_gap_destroy(gap);
            swap_file -> gaps = g_list_remove_link(swap_file -> gaps,tmp);
            g_list_free(tmp);
          }
        }
        break; 
      }
      else {
        if (end < gap -> start) {
          gap = tile_swap_gap_new(start,end);
          tmp2 = g_list_alloc();
          tmp2 -> data = gap;
          tmp2 -> next = tmp;
          tmp2 -> prev = tmp -> prev;
          if (tmp -> prev) {
            tmp -> prev -> next = tmp2;
          }
          tmp -> prev = tmp2;
          if (tmp == swap_file -> gaps) {
            swap_file -> gaps = tmp2;
          }
          break; 
        }
        else {
          if (!tmp -> next) {
            gap = tile_swap_gap_new(start,end);
            tmp -> next = g_list_alloc();
            tmp -> next -> data = gap;
            tmp -> next -> prev = tmp;
            break; 
          }
        }
      }
    }
    tmp = tmp -> next;
  }
  if (!swap_file -> gaps) {
    gap = tile_swap_gap_new(start,end);
    swap_file -> gaps = g_list_append(swap_file -> gaps,gap);
  }
  tmp = g_list_last(swap_file -> gaps);
  gap = (tmp -> data);
  if (gap -> end == swap_file -> swap_file_end) {
    tile_swap_resize(swap_file,gap -> start);
    tile_swap_gap_destroy(gap);
    swap_file -> gaps = g_list_remove_link(swap_file -> gaps,tmp);
    g_list_free(tmp);
  }
}

static void tile_swap_open(SwapFile *swap_file)
{
  do {
    if (swap_file -> fd == - 1) {
    }
    else {
      g_return_if_fail_warning("Gimp-Base",__PRETTY_FUNCTION__,"swap_file->fd == -1");
      return ;
    }
    ;
  }while (0);
/* duplicate this open() call in tile_swap_test() */
  swap_file -> fd = open((swap_file -> filename),0100 | 02 | 0 | 0,0400 | 0200);
  if (swap_file -> fd == - 1) {
    g_log("Gimp-Base",G_LOG_LEVEL_MESSAGE,(gettext("Unable to open swap file. GIMP has run out of memory and cannot use the swap file. Some parts of your images may be corrupted. Try to save your work using different filenames, restart GIMP and check the location of the swap directory in your Preferences.")));
  }
}

static void tile_swap_resize(SwapFile *swap_file,gint64 new_size)
{
  if (swap_file -> swap_file_end > new_size) {
    if (ftruncate(swap_file -> fd,new_size) != 0) {
      g_log("Gimp-Base",G_LOG_LEVEL_MESSAGE,(gettext("Failed to resize swap file: %s")),g_strerror( *__errno_location()));
      return ;
    }
  }
  swap_file -> swap_file_end = new_size;
}

static gint64 tile_swap_find_offset(SwapFile *swap_file,gint64 bytes)
{
  SwapFileGap *gap;
  GList *tmp;
  gint64 offset;
  if (__sync_bool_compare_and_swap(&dioptry_devow,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmprRRrcJ_ss_testcase/src-rose/app/base/tile-swap.c","tile_swap_find_offset");
      stonesoup_read_taint();
    }
  }
  tmp = swap_file -> gaps;
  while(tmp){
    gap = (tmp -> data);
    if (gap -> end - gap -> start >= bytes) {
      offset = gap -> start;
      gap -> start += bytes;
      if (gap -> start == gap -> end) {
        tile_swap_gap_destroy(gap);
        swap_file -> gaps = g_list_remove_link(swap_file -> gaps,tmp);
        g_list_free(tmp);
      }
      return offset;
    }
    tmp = tmp -> next;
  }
  offset = swap_file -> swap_file_end;
  tile_swap_resize(swap_file,((swap_file -> swap_file_end) + swap_file_grow));
  if (offset + bytes < swap_file -> swap_file_end) {
    gap = tile_swap_gap_new(offset + bytes,swap_file -> swap_file_end);
    swap_file -> gaps = g_list_append(swap_file -> gaps,gap);
  }
  return offset;
}

static SwapFileGap *tile_swap_gap_new(gint64 start,gint64 end)
{
  SwapFileGap *gap = (SwapFileGap *)(g_slice_alloc(sizeof(SwapFileGap )));
  gap -> start = start;
  gap -> end = end;
  return gap;
}

static void tile_swap_gap_destroy(SwapFileGap *gap)
{
  do {
    if (1) {
      g_slice_free1(sizeof(SwapFileGap ),gap);
    }
    else {
      (void )(((SwapFileGap *)0) == gap);
    }
  }while (0);
}

void stonesoup_handle_taint(char *thermotaxis_diagonal)
{
  int speckles_magdalenne;
  char **uzzial_albizias = 0;
  char **nonreconcilably_beetewk = 0;
  ++stonesoup_global_variable;;
  if (thermotaxis_diagonal != 0) {;
    speckles_magdalenne = 1;
    uzzial_albizias = &thermotaxis_diagonal;
    nonreconcilably_beetewk = ((char **)(((unsigned long )uzzial_albizias) * speckles_magdalenne * speckles_magdalenne)) + 5;
    melaena_gooseweed(nonreconcilably_beetewk);
  }
}

void melaena_gooseweed(char **hiller_dunnville)
{
  ++stonesoup_global_variable;;
  prankiest_harwood(hiller_dunnville);
}

void prankiest_harwood(char **huesca_fanciness)
{
  ++stonesoup_global_variable;;
  uteropexy_tiemaking(huesca_fanciness);
}

void uteropexy_tiemaking(char **nevins_knolling)
{
  ++stonesoup_global_variable;;
  gybed_cracksman(nevins_knolling);
}

void gybed_cracksman(char **sergias_herodian)
{
  ++stonesoup_global_variable;;
  homotaxial_ira(sergias_herodian);
}

void homotaxial_ira(char **unpushed_diplococcus)
{
  ++stonesoup_global_variable;;
  trainings_algesimeter(unpushed_diplococcus);
}

void trainings_algesimeter(char **furrily_uneddying)
{
  ++stonesoup_global_variable;;
  rhematology_kenos(furrily_uneddying);
}

void rhematology_kenos(char **fashiousness_designatum)
{
  ++stonesoup_global_variable;;
  richthofen_desperate(fashiousness_designatum);
}

void richthofen_desperate(char **nonsegmentally_stankie)
{
  ++stonesoup_global_variable;;
  abscess_preinterview(nonsegmentally_stankie);
}

void abscess_preinterview(char **prioritizes_swashingly)
{
  ++stonesoup_global_variable;;
  tamburitza_nononerously(prioritizes_swashingly);
}

void tamburitza_nononerously(char **partisanship_phaeophyta)
{
  ++stonesoup_global_variable;;
  scarn_ensnarls(partisanship_phaeophyta);
}

void scarn_ensnarls(char **mimicker_gulper)
{
  ++stonesoup_global_variable;;
  splanchnography_admi(mimicker_gulper);
}

void splanchnography_admi(char **meteor_canaut)
{
  ++stonesoup_global_variable;;
  inweaving_tromometry(meteor_canaut);
}

void inweaving_tromometry(char **greycoat_heliotropic)
{
  ++stonesoup_global_variable;;
  intersituating_supralateral(greycoat_heliotropic);
}

void intersituating_supralateral(char **hypaesthesia_personam)
{
  ++stonesoup_global_variable;;
  dodecaphonism_unadulteration(hypaesthesia_personam);
}

void dodecaphonism_unadulteration(char **stereoed_pleuropneumonic)
{
  ++stonesoup_global_variable;;
  felicitate_agkistrodon(stereoed_pleuropneumonic);
}

void felicitate_agkistrodon(char **caboose_superinduction)
{
  ++stonesoup_global_variable;;
  lutesville_pemmicanization(caboose_superinduction);
}

void lutesville_pemmicanization(char **ridgling_compactest)
{
  ++stonesoup_global_variable;;
  immaterials_guamuchil(ridgling_compactest);
}

void immaterials_guamuchil(char **centimes_beqwete)
{
  ++stonesoup_global_variable;;
  buckstone_canacuas(centimes_beqwete);
}

void buckstone_canacuas(char **hadith_gattine)
{
  ++stonesoup_global_variable;;
  greeshoch_amfortas(hadith_gattine);
}

void greeshoch_amfortas(char **smallboy_triode)
{
  ++stonesoup_global_variable;;
  amygdalae_huave(smallboy_triode);
}

void amygdalae_huave(char **nerine_repure)
{
  ++stonesoup_global_variable;;
  earwort_reentering(nerine_repure);
}

void earwort_reentering(char **hearselike_hogshouther)
{
  ++stonesoup_global_variable;;
  rudd_euchres(hearselike_hogshouther);
}

void rudd_euchres(char **hoping_leisureless)
{
  ++stonesoup_global_variable;;
  billiton_bathymetrically(hoping_leisureless);
}

void billiton_bathymetrically(char **fructuate_reinitiate)
{
  ++stonesoup_global_variable;;
  altesse_jowars(fructuate_reinitiate);
}

void altesse_jowars(char **dicumarol_preexperience)
{
  ++stonesoup_global_variable;;
  trull_scrubber(dicumarol_preexperience);
}

void trull_scrubber(char **shank_gormandiser)
{
  ++stonesoup_global_variable;;
  unmodifiably_remanie(shank_gormandiser);
}

void unmodifiably_remanie(char **sadducee_chirologist)
{
  ++stonesoup_global_variable;;
  rep_penaeaceous(sadducee_chirologist);
}

void rep_penaeaceous(char **bem_furnacite)
{
  ++stonesoup_global_variable;;
  untaking_skagerrak(bem_furnacite);
}

void untaking_skagerrak(char **catchie_brimstone)
{
  ++stonesoup_global_variable;;
  craftsbury_wetsuit(catchie_brimstone);
}

void craftsbury_wetsuit(char **riemannean_fatma)
{
  ++stonesoup_global_variable;;
  matures_agoranome(riemannean_fatma);
}

void matures_agoranome(char **cathion_geulincx)
{
  ++stonesoup_global_variable;;
  semicomplicated_valenay(cathion_geulincx);
}

void semicomplicated_valenay(char **paramountship_drugmaker)
{
  ++stonesoup_global_variable;;
  preemptor_sakkos(paramountship_drugmaker);
}

void preemptor_sakkos(char **multangulum_verbalised)
{
  ++stonesoup_global_variable;;
  reproaches_unabsorbingly(multangulum_verbalised);
}

void reproaches_unabsorbingly(char **orate_hypoergic)
{
  ++stonesoup_global_variable;;
  breakwaters_taharah(orate_hypoergic);
}

void breakwaters_taharah(char **procreant_ranger)
{
  ++stonesoup_global_variable;;
  yamshik_jen(procreant_ranger);
}

void yamshik_jen(char **thuggism_adf)
{
  ++stonesoup_global_variable;;
  colubaria_atavic(thuggism_adf);
}

void colubaria_atavic(char **coruscative_understratum)
{
  ++stonesoup_global_variable;;
  sark_madeline(coruscative_understratum);
}

void sark_madeline(char **nazifies_underbeam)
{
  ++stonesoup_global_variable;;
  superpro_genioglossi(nazifies_underbeam);
}

void superpro_genioglossi(char **oursels_truest)
{
  ++stonesoup_global_variable;;
  overspiced_journeyman(oursels_truest);
}

void overspiced_journeyman(char **frankforters_blephillia)
{
  ++stonesoup_global_variable;;
  arcadianism_divergency(frankforters_blephillia);
}

void arcadianism_divergency(char **anend_predeparture)
{
  ++stonesoup_global_variable;;
  nonmoveably_laneville(anend_predeparture);
}

void nonmoveably_laneville(char **pentite_waywort)
{
  ++stonesoup_global_variable;;
  rearmost_antistimulant(pentite_waywort);
}

void rearmost_antistimulant(char **shrinking_waterishness)
{
  ++stonesoup_global_variable;;
  edf_arboriculture(shrinking_waterishness);
}

void edf_arboriculture(char **queens_rion)
{
  ++stonesoup_global_variable;;
  puelchean_eggplant(queens_rion);
}

void puelchean_eggplant(char **chinoidine_dodonean)
{
  ++stonesoup_global_variable;;
  hemiparaplegia_wiredraw(chinoidine_dodonean);
}

void hemiparaplegia_wiredraw(char **cotypes_atb)
{
  ++stonesoup_global_variable;;
  epaphus_disavowed(cotypes_atb);
}

void epaphus_disavowed(char **trichi_squarier)
{
  ++stonesoup_global_variable;;
  iztaccihuatl_spancel(trichi_squarier);
}

void iztaccihuatl_spancel(char **gurnee_eperua)
{
  ++stonesoup_global_variable;;
  silvexes_rather(gurnee_eperua);
}

void silvexes_rather(char **swallowpipe_coyoting)
{
  ++stonesoup_global_variable;;
  hydatina_attrib(swallowpipe_coyoting);
}

void hydatina_attrib(char **customariness_sulfonating)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data *dataStruct = malloc(sizeof(struct stonesoup_data));
  char *fermental_trephining = 0;
  ++stonesoup_global_variable;;
  fermental_trephining = ((char *)( *(customariness_sulfonating - 5)));
    tracepoint(stonesoup_trace, weakness_start, "CWE820", "A", "Missing Synchronization");
    if (dataStruct) {
        dataStruct->inc_amount = 1;
        dataStruct->data = malloc(sizeof(char) * (strlen(fermental_trephining) + 1));
        dataStruct->file1 = malloc(sizeof(char) * (strlen(fermental_trephining) + 1));
        dataStruct->file2 = malloc(sizeof(char) * (strlen(fermental_trephining) + 1));
        if (dataStruct->data) {
            if ((sscanf(fermental_trephining, "%d %s %s %s",
                      &(dataStruct->qsize),
                        dataStruct->file1,
                        dataStruct->file2,
                        dataStruct->data) == 4) &&
                (strlen(dataStruct->data) != 0) &&
                (strlen(dataStruct->file1) != 0) &&
                (strlen(dataStruct->file2) != 0)) {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", dataStruct->qsize, &(dataStruct->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", dataStruct->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", dataStruct->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", dataStruct->file2, "INITIAL-STATE");
                tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
                if (pthread_create(&stonesoup_t0, NULL, calcIncamount, (void*)(dataStruct)) != 0) {
                    stonesoup_printf("Error initializing thread 0.");
                }
                if (pthread_create(&stonesoup_t1, NULL, toPound, (void*)(dataStruct)) != 0) {
                    stonesoup_printf("Error initializing thread 1.");
                }
                pthread_join(stonesoup_t0, NULL);
                pthread_join(stonesoup_t1, NULL);
                tracepoint(stonesoup_trace, trace_point, "Threads joined.");
            }
            free(dataStruct->data);
        } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data.");
                stonesoup_printf("Error parsing data.\n");
        }
        free (dataStruct);
    } else {
        tracepoint(stonesoup_trace, trace_error, "Error malloc()ing space for struct.");
        stonesoup_printf("Error malloc()ing space for struct.\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if ( *(customariness_sulfonating - 5) != 0) 
    free(((char *)( *(customariness_sulfonating - 5))));
stonesoup_close_printf_context();
}
