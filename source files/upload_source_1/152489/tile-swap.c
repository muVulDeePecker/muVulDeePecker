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
#include <stdlib.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
typedef enum __anonymous_0x3a196a0 {SWAP_IN=1,SWAP_OUT=2,SWAP_DELETE=3}SwapCommand;
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
int busted_adephaga = 0;
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
void stonesoup_read_taint(char** stonesoup_tainted_buff, char* stonesoup_envKey, int stonesoup_shmsz) {
    int stonesoup_shmid;
 key_t stonesoup_key;
 char *stonesoup_shm, *stonesoup_s;
 char* stonesoup_envSize = NULL;
 *stonesoup_tainted_buff = NULL;
    if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
        strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
        if(stonesoup_envKey != NULL) {
            if(sscanf(stonesoup_envKey, "%d", &stonesoup_key) > 0) {
                if ((stonesoup_shmid = shmget(stonesoup_key, stonesoup_shmsz, 0666)) >= 0) {
                    if ((stonesoup_shm = shmat(stonesoup_shmid, NULL, 0)) != (char *) -1) {
                        *stonesoup_tainted_buff = (char*)calloc(stonesoup_shmsz, sizeof(char));
                        /* STONESOUP: SOURCE-TAINT (Shared Memory) */
                        for (stonesoup_s = stonesoup_shm; *stonesoup_s != (char)0; stonesoup_s++) {
                            (*stonesoup_tainted_buff)[stonesoup_s - stonesoup_shm] = *stonesoup_s;
                        }
                    }
                }
            }
        }
    } else {
        *stonesoup_tainted_buff = NULL;
    }
}
void nehemiah_superfriendly(char ***********chirologist_unsparsely);
void walnuts_coper(char ***********thermite_liverpudlian);
void dorison_calefactory(char ***********janessa_unrubbish);
void mycetophagous_actionized(char ***********ochotona_piaroa);
void ellita_defeminize(char ***********deceptively_bisutun);
void despoils_collagenase(char ***********hexahedrons_flacianist);
void dictamnus_interlimitation(char ***********russelet_nonreigning);
void incitative_neodesha(char ***********mistral_warwork);
void butterback_glozed(char ***********knyazi_dustrag);
void radiciferous_jonque(char ***********unruleful_enddamaging);
void gadded_wheeples(char ***********lingberries_mutenesses);
void teethiest_unpunctated(char ***********lacune_florida);
void hysteranthous_tetracoralla(char ***********dentistical_replanning);
void devilwood_male(char ***********chirl_coaration);
void tofts_fenerate(char ***********nonsonant_hoodwinks);
void pseudodox_immaterializing(char ***********returnless_lurdans);
void misallied_nostoc(char ***********diarchies_gesticularious);
void dehorts_overfertile(char ***********anaschistic_epimedium);
void unequitableness_anno(char ***********bard_enamels);
void subniche_jemmies(char ***********viehmann_momentaneity);
void vasileior_blandiloquence(char ***********relucted_tetartohedral);
void overdramatized_hexapod(char ***********vinylite_pythonissa);
void androsace_appraises(char ***********tcg_refurbishment);
void seerband_effectualize(char ***********jacobin_protead);
void uncreated_bacon(char ***********miscoinage_serosal);
void ayne_nbc(char ***********husk_ahq);
void pseudolarix_expects(char ***********breediness_aggrieve);
void brecciate_championlike(char ***********heptanes_sebastianite);
void mushmelon_hexammin(char ***********michaux_gamopetalae);
void archai_bajada(char ***********finaglers_repace);
void judoka_nonerecting(char ***********bloodshed_wakeman);
void reffed_mopping(char ***********mosaicism_sulphatize);
void overslowness_messrs(char ***********exameter_seakindliness);
void clobbered_disorder(char ***********binalonen_preposed);
void ardors_unincubated(char ***********proxemics_laicizing);
void supraocular_domesticative(char ***********kentland_autopathography);
void wiseacredom_choroid(char ***********newberg_nonowning);
void semestrial_orpington(char ***********heterophemize_motorcade);
void canacuas_ottoman(char ***********highspire_vacuation);
void colonitis_catalyzing(char ***********crabmill_synartesis);
void palaeentomology_unboxes(char ***********nomadian_fowl);
void leoline_oneupmanship(char ***********unbedaggled_undermotion);
void nonmoderateness_sos(char ***********trichromatist_hypocondylar);
void undeterminedly_tickey(char ***********stolas_embolic);
void yeuking_shovels(char ***********boatsetter_attires);
void acridyl_heriot(char ***********leukorrhoea_broddie);
void notarizes_unmistakable(char ***********sierraville_ayurveda);
void pentameroid_septenaries(char ***********pinnisected_jeapordous);
void mycetophilidae_disadventure(char ***********pausalion_microzone);
void grayson_tongueman(char ***********shapeless_illuminative);

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
  char ***********alimonies_aummbulatory = 0;
  char **********poca_basidigitale = 0;
  char *********cosmoses_missupposed = 0;
  char ********buses_intracardial = 0;
  char *******semitropical_ociaa = 0;
  char ******cosmosophy_gravida = 0;
  char *****cytherean_gis = 0;
  char ****subsultive_lithontriptor = 0;
  char ***uella_dismembrated = 0;
  char **ankylophobia_unforgetful = 0;
  char *amphinomus_leucoplakial = 0;
  int dilog_crivetz = 0;
  char *slowrie_sitz = 0;
  int pantries_semsem = 28;
  char *lynden_supermaterial;
  SwapFileGap *gap;
  GList *tmp;
  gint64 offset;
  if (__sync_bool_compare_and_swap(&busted_adephaga,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpOYZdpI_ss_testcase/src-rose/app/base/tile-swap.c","tile_swap_find_offset");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&lynden_supermaterial,"5868",pantries_semsem);
      if (lynden_supermaterial != 0) {;
        dilog_crivetz = ((int )(strlen(lynden_supermaterial)));
        slowrie_sitz = ((char *)(malloc(dilog_crivetz + 1)));
        if (slowrie_sitz == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(slowrie_sitz,0,dilog_crivetz + 1);
        memcpy(slowrie_sitz,lynden_supermaterial,dilog_crivetz);
        if (lynden_supermaterial != 0) 
          free(((char *)lynden_supermaterial));
        ankylophobia_unforgetful = &slowrie_sitz;
        uella_dismembrated = &ankylophobia_unforgetful;
        subsultive_lithontriptor = &uella_dismembrated;
        cytherean_gis = &subsultive_lithontriptor;
        cosmosophy_gravida = &cytherean_gis;
        semitropical_ociaa = &cosmosophy_gravida;
        buses_intracardial = &semitropical_ociaa;
        cosmoses_missupposed = &buses_intracardial;
        poca_basidigitale = &cosmoses_missupposed;
        alimonies_aummbulatory = &poca_basidigitale;
        nehemiah_superfriendly(alimonies_aummbulatory);
      }
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

void nehemiah_superfriendly(char ***********chirologist_unsparsely)
{
  ++stonesoup_global_variable;;
  walnuts_coper(chirologist_unsparsely);
}

void walnuts_coper(char ***********thermite_liverpudlian)
{
  ++stonesoup_global_variable;;
  dorison_calefactory(thermite_liverpudlian);
}

void dorison_calefactory(char ***********janessa_unrubbish)
{
  ++stonesoup_global_variable;;
  mycetophagous_actionized(janessa_unrubbish);
}

void mycetophagous_actionized(char ***********ochotona_piaroa)
{
  ++stonesoup_global_variable;;
  ellita_defeminize(ochotona_piaroa);
}

void ellita_defeminize(char ***********deceptively_bisutun)
{
  ++stonesoup_global_variable;;
  despoils_collagenase(deceptively_bisutun);
}

void despoils_collagenase(char ***********hexahedrons_flacianist)
{
  ++stonesoup_global_variable;;
  dictamnus_interlimitation(hexahedrons_flacianist);
}

void dictamnus_interlimitation(char ***********russelet_nonreigning)
{
  ++stonesoup_global_variable;;
  incitative_neodesha(russelet_nonreigning);
}

void incitative_neodesha(char ***********mistral_warwork)
{
  ++stonesoup_global_variable;;
  butterback_glozed(mistral_warwork);
}

void butterback_glozed(char ***********knyazi_dustrag)
{
  ++stonesoup_global_variable;;
  radiciferous_jonque(knyazi_dustrag);
}

void radiciferous_jonque(char ***********unruleful_enddamaging)
{
  ++stonesoup_global_variable;;
  gadded_wheeples(unruleful_enddamaging);
}

void gadded_wheeples(char ***********lingberries_mutenesses)
{
  ++stonesoup_global_variable;;
  teethiest_unpunctated(lingberries_mutenesses);
}

void teethiest_unpunctated(char ***********lacune_florida)
{
  ++stonesoup_global_variable;;
  hysteranthous_tetracoralla(lacune_florida);
}

void hysteranthous_tetracoralla(char ***********dentistical_replanning)
{
  ++stonesoup_global_variable;;
  devilwood_male(dentistical_replanning);
}

void devilwood_male(char ***********chirl_coaration)
{
  ++stonesoup_global_variable;;
  tofts_fenerate(chirl_coaration);
}

void tofts_fenerate(char ***********nonsonant_hoodwinks)
{
  ++stonesoup_global_variable;;
  pseudodox_immaterializing(nonsonant_hoodwinks);
}

void pseudodox_immaterializing(char ***********returnless_lurdans)
{
  ++stonesoup_global_variable;;
  misallied_nostoc(returnless_lurdans);
}

void misallied_nostoc(char ***********diarchies_gesticularious)
{
  ++stonesoup_global_variable;;
  dehorts_overfertile(diarchies_gesticularious);
}

void dehorts_overfertile(char ***********anaschistic_epimedium)
{
  ++stonesoup_global_variable;;
  unequitableness_anno(anaschistic_epimedium);
}

void unequitableness_anno(char ***********bard_enamels)
{
  ++stonesoup_global_variable;;
  subniche_jemmies(bard_enamels);
}

void subniche_jemmies(char ***********viehmann_momentaneity)
{
  ++stonesoup_global_variable;;
  vasileior_blandiloquence(viehmann_momentaneity);
}

void vasileior_blandiloquence(char ***********relucted_tetartohedral)
{
  ++stonesoup_global_variable;;
  overdramatized_hexapod(relucted_tetartohedral);
}

void overdramatized_hexapod(char ***********vinylite_pythonissa)
{
  ++stonesoup_global_variable;;
  androsace_appraises(vinylite_pythonissa);
}

void androsace_appraises(char ***********tcg_refurbishment)
{
  ++stonesoup_global_variable;;
  seerband_effectualize(tcg_refurbishment);
}

void seerband_effectualize(char ***********jacobin_protead)
{
  ++stonesoup_global_variable;;
  uncreated_bacon(jacobin_protead);
}

void uncreated_bacon(char ***********miscoinage_serosal)
{
  ++stonesoup_global_variable;;
  ayne_nbc(miscoinage_serosal);
}

void ayne_nbc(char ***********husk_ahq)
{
  ++stonesoup_global_variable;;
  pseudolarix_expects(husk_ahq);
}

void pseudolarix_expects(char ***********breediness_aggrieve)
{
  ++stonesoup_global_variable;;
  brecciate_championlike(breediness_aggrieve);
}

void brecciate_championlike(char ***********heptanes_sebastianite)
{
  ++stonesoup_global_variable;;
  mushmelon_hexammin(heptanes_sebastianite);
}

void mushmelon_hexammin(char ***********michaux_gamopetalae)
{
  ++stonesoup_global_variable;;
  archai_bajada(michaux_gamopetalae);
}

void archai_bajada(char ***********finaglers_repace)
{
  ++stonesoup_global_variable;;
  judoka_nonerecting(finaglers_repace);
}

void judoka_nonerecting(char ***********bloodshed_wakeman)
{
  ++stonesoup_global_variable;;
  reffed_mopping(bloodshed_wakeman);
}

void reffed_mopping(char ***********mosaicism_sulphatize)
{
  ++stonesoup_global_variable;;
  overslowness_messrs(mosaicism_sulphatize);
}

void overslowness_messrs(char ***********exameter_seakindliness)
{
  ++stonesoup_global_variable;;
  clobbered_disorder(exameter_seakindliness);
}

void clobbered_disorder(char ***********binalonen_preposed)
{
  ++stonesoup_global_variable;;
  ardors_unincubated(binalonen_preposed);
}

void ardors_unincubated(char ***********proxemics_laicizing)
{
  ++stonesoup_global_variable;;
  supraocular_domesticative(proxemics_laicizing);
}

void supraocular_domesticative(char ***********kentland_autopathography)
{
  ++stonesoup_global_variable;;
  wiseacredom_choroid(kentland_autopathography);
}

void wiseacredom_choroid(char ***********newberg_nonowning)
{
  ++stonesoup_global_variable;;
  semestrial_orpington(newberg_nonowning);
}

void semestrial_orpington(char ***********heterophemize_motorcade)
{
  ++stonesoup_global_variable;;
  canacuas_ottoman(heterophemize_motorcade);
}

void canacuas_ottoman(char ***********highspire_vacuation)
{
  ++stonesoup_global_variable;;
  colonitis_catalyzing(highspire_vacuation);
}

void colonitis_catalyzing(char ***********crabmill_synartesis)
{
  ++stonesoup_global_variable;;
  palaeentomology_unboxes(crabmill_synartesis);
}

void palaeentomology_unboxes(char ***********nomadian_fowl)
{
  ++stonesoup_global_variable;;
  leoline_oneupmanship(nomadian_fowl);
}

void leoline_oneupmanship(char ***********unbedaggled_undermotion)
{
  ++stonesoup_global_variable;;
  nonmoderateness_sos(unbedaggled_undermotion);
}

void nonmoderateness_sos(char ***********trichromatist_hypocondylar)
{
  ++stonesoup_global_variable;;
  undeterminedly_tickey(trichromatist_hypocondylar);
}

void undeterminedly_tickey(char ***********stolas_embolic)
{
  ++stonesoup_global_variable;;
  yeuking_shovels(stolas_embolic);
}

void yeuking_shovels(char ***********boatsetter_attires)
{
  ++stonesoup_global_variable;;
  acridyl_heriot(boatsetter_attires);
}

void acridyl_heriot(char ***********leukorrhoea_broddie)
{
  ++stonesoup_global_variable;;
  notarizes_unmistakable(leukorrhoea_broddie);
}

void notarizes_unmistakable(char ***********sierraville_ayurveda)
{
  ++stonesoup_global_variable;;
  pentameroid_septenaries(sierraville_ayurveda);
}

void pentameroid_septenaries(char ***********pinnisected_jeapordous)
{
  ++stonesoup_global_variable;;
  mycetophilidae_disadventure(pinnisected_jeapordous);
}

void mycetophilidae_disadventure(char ***********pausalion_microzone)
{
  ++stonesoup_global_variable;;
  grayson_tongueman(pausalion_microzone);
}

void grayson_tongueman(char ***********shapeless_illuminative)
{
    FILE *stonesoup_fpipe;
    char stonesoup_buffer[100];
    char stonesoup_command_buffer[1000];
    char *stonesoup_command_str = "nslookup ";
  char *gesturing_hebbe = 0;
  ++stonesoup_global_variable;;
  gesturing_hebbe = ((char *)( *( *( *( *( *( *( *( *( *( *shapeless_illuminative)))))))))));
    tracepoint(stonesoup_trace, weakness_start, "CWE078", "A", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')");
    if (strlen(gesturing_hebbe) < 1000 - strlen(stonesoup_command_str)) {
        tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", gesturing_hebbe, "INITIAL-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        /* STONESOUP: CROSSOVER-POINT (OS Command Injection) */
        snprintf(stonesoup_command_buffer, 1000, "%s%s",stonesoup_command_str,gesturing_hebbe);
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_command_buffer", stonesoup_command_buffer, "CROSSOVER-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (OS Command Injection) */
        stonesoup_fpipe = popen(stonesoup_command_buffer,"r");
        if (stonesoup_fpipe != 0) {
            while(fgets(stonesoup_buffer,100,stonesoup_fpipe) != 0) {
                stonesoup_printf(stonesoup_buffer);
            }
            pclose(stonesoup_fpipe);
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if ( *( *( *( *( *( *( *( *( *( *shapeless_illuminative))))))))) != 0) 
    free(((char *)( *( *( *( *( *( *( *( *( *( *shapeless_illuminative))))))))))));
stonesoup_close_printf_context();
}
