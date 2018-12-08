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
#include <stonesoup/stonesoup_trace.h> 
typedef enum __anonymous_0x3c6c6a0 {SWAP_IN=1,SWAP_OUT=2,SWAP_DELETE=3}SwapCommand;
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
int febronian_marcellianism = 0;
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
void redo_darby(char *astrologies_peramium);

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
  void (*daberath_tabic)(char *) = redo_darby;
  char *heightened_eleuthera = 0;
  int **************************************************marouflage_ungenerously = 0;
  int *************************************************pullbacks_richton = 0;
  int ************************************************imbues_eldritch = 0;
  int ***********************************************halid_pausefully = 0;
  int **********************************************stunners_lemna = 0;
  int *********************************************navig_metope = 0;
  int ********************************************boletuses_salicin = 0;
  int *******************************************jorgan_arethuse = 0;
  int ******************************************juicelessness_addicted = 0;
  int *****************************************nockerl_sadisms = 0;
  int ****************************************rigel_noninhabitancy = 0;
  int ***************************************beachheads_palaeothentes = 0;
  int **************************************largeous_overharshly = 0;
  int *************************************foggily_tendomucoid = 0;
  int ************************************tutorkey_lief = 0;
  int ***********************************shipful_neomenia = 0;
  int **********************************awl_delphocurarine = 0;
  int *********************************barbet_catabasis = 0;
  int ********************************depriment_subpericardiac = 0;
  int *******************************geomorphy_dirhams = 0;
  int ******************************marliest_huccatoon = 0;
  int *****************************potassiums_lymphation = 0;
  int ****************************megalography_vicecomites = 0;
  int ***************************ravishes_unneutralising = 0;
  int **************************unspecterlike_jellico = 0;
  int *************************tigger_vernice = 0;
  int ************************galactocele_resprout = 0;
  int ***********************blood_colostral = 0;
  int **********************southwardly_urana = 0;
  int *********************etiotropically_electrize = 0;
  int ********************notative_egocentristic = 0;
  int *******************discrepated_subalgebraic = 0;
  int ******************ginkgos_mantas = 0;
  int *****************nonpapal_effectualize = 0;
  int ****************bedewed_villeity = 0;
  int ***************salic_unguardedness = 0;
  int **************antenati_gilberts = 0;
  int *************pact_stomate = 0;
  int ************futurists_bath = 0;
  int ***********vulgarians_estopping = 0;
  int **********teletopometer_heartbreakingly = 0;
  int *********nonactual_jumprock = 0;
  int ********unauthorized_fris = 0;
  int *******ponce_wogul = 0;
  int ******calamars_toiletted = 0;
  int *****crackup_polypeptide = 0;
  int ****nonbarbaric_bromometry = 0;
  int ***seigniorial_accessions = 0;
  int **entobranchiate_nazdrowie = 0;
  int *rehook_ovistic = 0;
  int boilinglike_earbob;
  char *platycercinae_jgr[10] = {0};
  char *bivariate_rakestele;
  SwapFileGap *gap;
  GList *tmp;
  gint64 offset;
  if (__sync_bool_compare_and_swap(&febronian_marcellianism,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpOjoOJD_ss_testcase/src-rose/app/base/tile-swap.c","tile_swap_find_offset");
      stonesoup_setup_printf_context();
      bivariate_rakestele = getenv("OVIVOROUS_TBILISI");
      if (bivariate_rakestele != 0) {;
        boilinglike_earbob = 5;
        rehook_ovistic = &boilinglike_earbob;
        entobranchiate_nazdrowie = &rehook_ovistic;
        seigniorial_accessions = &entobranchiate_nazdrowie;
        nonbarbaric_bromometry = &seigniorial_accessions;
        crackup_polypeptide = &nonbarbaric_bromometry;
        calamars_toiletted = &crackup_polypeptide;
        ponce_wogul = &calamars_toiletted;
        unauthorized_fris = &ponce_wogul;
        nonactual_jumprock = &unauthorized_fris;
        teletopometer_heartbreakingly = &nonactual_jumprock;
        vulgarians_estopping = &teletopometer_heartbreakingly;
        futurists_bath = &vulgarians_estopping;
        pact_stomate = &futurists_bath;
        antenati_gilberts = &pact_stomate;
        salic_unguardedness = &antenati_gilberts;
        bedewed_villeity = &salic_unguardedness;
        nonpapal_effectualize = &bedewed_villeity;
        ginkgos_mantas = &nonpapal_effectualize;
        discrepated_subalgebraic = &ginkgos_mantas;
        notative_egocentristic = &discrepated_subalgebraic;
        etiotropically_electrize = &notative_egocentristic;
        southwardly_urana = &etiotropically_electrize;
        blood_colostral = &southwardly_urana;
        galactocele_resprout = &blood_colostral;
        tigger_vernice = &galactocele_resprout;
        unspecterlike_jellico = &tigger_vernice;
        ravishes_unneutralising = &unspecterlike_jellico;
        megalography_vicecomites = &ravishes_unneutralising;
        potassiums_lymphation = &megalography_vicecomites;
        marliest_huccatoon = &potassiums_lymphation;
        geomorphy_dirhams = &marliest_huccatoon;
        depriment_subpericardiac = &geomorphy_dirhams;
        barbet_catabasis = &depriment_subpericardiac;
        awl_delphocurarine = &barbet_catabasis;
        shipful_neomenia = &awl_delphocurarine;
        tutorkey_lief = &shipful_neomenia;
        foggily_tendomucoid = &tutorkey_lief;
        largeous_overharshly = &foggily_tendomucoid;
        beachheads_palaeothentes = &largeous_overharshly;
        rigel_noninhabitancy = &beachheads_palaeothentes;
        nockerl_sadisms = &rigel_noninhabitancy;
        juicelessness_addicted = &nockerl_sadisms;
        jorgan_arethuse = &juicelessness_addicted;
        boletuses_salicin = &jorgan_arethuse;
        navig_metope = &boletuses_salicin;
        stunners_lemna = &navig_metope;
        halid_pausefully = &stunners_lemna;
        imbues_eldritch = &halid_pausefully;
        pullbacks_richton = &imbues_eldritch;
        marouflage_ungenerously = &pullbacks_richton;
        platycercinae_jgr[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *marouflage_ungenerously)))))))))))))))))))))))))))))))))))))))))))))))))] = bivariate_rakestele;
        heightened_eleuthera = platycercinae_jgr[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *marouflage_ungenerously)))))))))))))))))))))))))))))))))))))))))))))))))];
        daberath_tabic(heightened_eleuthera);
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

void redo_darby(char *astrologies_peramium)
{
 long long stonesoup_check_val = 2LL;
 long long stonesoup_in_val;
 int prime = 1;
  char *owly_beseemed = 0;
  ++stonesoup_global_variable;;
  owly_beseemed = ((char *)astrologies_peramium);
    tracepoint(stonesoup_trace, weakness_start, "CWE834", "A", "Excessive Iteration");
    stonesoup_in_val = atoll(owly_beseemed);
    if (stonesoup_in_val > 1) {
        stonesoup_printf("Checking for primality\n");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_in_val", stonesoup_in_val, &stonesoup_in_val, "TRIGGER-STATE");
        for (; stonesoup_check_val <= stonesoup_in_val - 1; ++stonesoup_check_val){
            /* STONESOUP: CROSSOVER-POINT (Excessive Iteration) */
            /* STONESOUP: TRIGGER-POINT (Excessive Iteration) */
            if (stonesoup_in_val % stonesoup_check_val == 0) {
                prime = 0;
                break;
            }
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        if (prime) {
            stonesoup_printf("%lld is prime\n", stonesoup_in_val);
        } else {
            stonesoup_printf("%lld is composite\n", stonesoup_in_val);
        }
    } else {
        stonesoup_printf("Input value is less than or equal to 1\n");
    }
    stonesoup_printf("finished evaluating\n");
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
