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
typedef enum __anonymous_0x3c819f0 {SWAP_IN=1,SWAP_OUT=2,SWAP_DELETE=3}SwapCommand;
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
int prestudiousness_reaudition = 0;
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
void gauffer_endocarditic(char **gladiatrix_sabertooth);
void aix_samaritaness(char **understated_tippecanoe);
void kestrels_glareworm(char **gamasid_tonicobalsamic);
void fluidimeter_visions(char **shuddersome_cornelle);
void sequa_leaseback(char **topographers_unfeelingly);
void soinski_melanistic(char **chasse_pantagruelism);
void sycamore_flaxman(char **recessionary_coitions);
void polysiphonous_fister(char **pshaws_dystopian);
void presentor_ferio(char **belittle_palecek);
void keggmiengg_physiatrics(char **golliner_unframableness);
void neurergic_culmen(char **waterloggedness_kienan);
void tanta_carbohydraturia(char **ond_redeemedness);
void lipopexia_anaetiological(char **sapskull_nonaddict);
void controversional_palapala(char **murgeon_binodous);
void hogo_velocipedal(char **interstimulated_pure);
void caviares_smolder(char **kazatske_hexanaphthene);
void refuters_guestwise(char **voidableness_morin);
void superseaman_anoplanthus(char **missies_dorita);
void bombycinous_heterodontoid(char **ratooners_whickering);
void rais_quaintise(char **unwearisomeness_strychnos);
void unpassing_outcharm(char **vamoose_inkindle);
void antiannexation_melilites(char **millionaire_gynics);
void unobliterated_overlargely(char **lactonize_bradyglossia);
void fraised_starchier(char **reliquian_leptorrhinian);
void decatyl_blastular(char **twelvemo_dizzyingly);
void ruthlessness_orotinan(char **laurelship_posology);
void menshevist_perpetualness(char **dooket_acushla);
void otelia_spica(char **sphygmometric_summerlee);
void tinselling_subdatary(char **imitt_nonmalignant);
void surrogated_piassavas(char **juvenolatry_brute);
void halftones_hussydom(char **tinned_intrabiontic);
void eucairite_capsomere(char **spongioblastic_zervanite);
void pickaxed_subfields(char **dobsons_chadic);
void mouille_dogbody(char **octanols_tauryl);
void ballow_skidi(char **veiner_umbilicaria);
void dworman_oflete(char **joinvile_townships);
void cubitocarpal_bespattering(char **readopted_strikebreaker);
void goannas_postdiagnostic(char **billowing_coleosporium);
void vulguses_cloot(char **armorers_unwired);
void haptophor_osiridean(char **tampions_hemophile);
void discretiveness_brahma(char **vinylethylene_chilopoda);
void disadventure_wolfcoal(char **aap_myrabalanus);
void brawler_foreseen(char **basification_thunbergia);
void injudiciousness_trochee(char **disinure_menazons);
void benthamism_erbia(char **aeried_sketchers);
void wilfulness_includes(char **anciently_outwashes);
void pegs_macadam(char **pierre_northman);
void neophytes_inhibitive(char **elaidic_overtrouble);
void platycercinae_psychostatical(char **teethiest_cretinistic);
void sanitaries_forebrain(char **rhodinol_substraction);

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
  char **upas_overscrupulous = 0;
  int **************************************************yoldring_carnaubic = 0;
  int *************************************************unexorcisably_aerobiosis = 0;
  int ************************************************denasalize_snobscat = 0;
  int ***********************************************huskwort_decrepit = 0;
  int **********************************************unspotted_rondellier = 0;
  int *********************************************kaffia_tainting = 0;
  int ********************************************chemosis_carbin = 0;
  int *******************************************tressier_ousels = 0;
  int ******************************************saltines_obturator = 0;
  int *****************************************marchese_hydraulicking = 0;
  int ****************************************oncoses_aquarelle = 0;
  int ***************************************duperrault_ladydom = 0;
  int **************************************manoah_pheophyl = 0;
  int *************************************teleologist_clingfishes = 0;
  int ************************************overbodice_gralloch = 0;
  int ***********************************ernald_spirochetal = 0;
  int **********************************crusts_dolorously = 0;
  int *********************************merchantish_convexness = 0;
  int ********************************pigmentation_fecklessly = 0;
  int *******************************overadvanced_starnel = 0;
  int ******************************following_deluster = 0;
  int *****************************longee_anoetic = 0;
  int ****************************tsktsk_bovate = 0;
  int ***************************gruelings_latten = 0;
  int **************************roaring_propria = 0;
  int *************************naperer_bournless = 0;
  int ************************photopic_overexcitements = 0;
  int ***********************towmonts_sparrow = 0;
  int **********************andreaea_bundweed = 0;
  int *********************lecaniid_badmash = 0;
  int ********************subdemonstrated_shana = 0;
  int *******************polytope_badass = 0;
  int ******************lanterns_podophyllotoxin = 0;
  int *****************politicize_chowries = 0;
  int ****************craniognosy_nonworking = 0;
  int ***************chattel_outtrail = 0;
  int **************phia_toolholding = 0;
  int *************mentor_bedwell = 0;
  int ************marion_spermatolysis = 0;
  int ***********altesse_piccini = 0;
  int **********overstocks_wot = 0;
  int *********hydrodamalidae_bahutu = 0;
  int ********scutellaria_multifarously = 0;
  int *******undetrimental_chromene = 0;
  int ******wangles_evelong = 0;
  int *****cyanotic_rubberising = 0;
  int ****palatineship_poppycock = 0;
  int ***palaeostylic_corpn = 0;
  int **lappish_ricercars = 0;
  int *outsatisfied_crizzel = 0;
  int belies_senhoras;
  char **botnick_ortman[10] = {0};
  char *bradyseismism_voters[12] = {0};
  char *cabresta_kendy;
  SwapFileGap *gap;
  GList *tmp;
  gint64 offset;
  if (__sync_bool_compare_and_swap(&prestudiousness_reaudition,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpq5dtVK_ss_testcase/src-rose/app/base/tile-swap.c","tile_swap_find_offset");
      stonesoup_setup_printf_context();
      cabresta_kendy = getenv("UROTOXIA_PREMORTALLY");
      if (cabresta_kendy != 0) {;
        bradyseismism_voters[0] = cabresta_kendy;
        belies_senhoras = 5;
        outsatisfied_crizzel = &belies_senhoras;
        lappish_ricercars = &outsatisfied_crizzel;
        palaeostylic_corpn = &lappish_ricercars;
        palatineship_poppycock = &palaeostylic_corpn;
        cyanotic_rubberising = &palatineship_poppycock;
        wangles_evelong = &cyanotic_rubberising;
        undetrimental_chromene = &wangles_evelong;
        scutellaria_multifarously = &undetrimental_chromene;
        hydrodamalidae_bahutu = &scutellaria_multifarously;
        overstocks_wot = &hydrodamalidae_bahutu;
        altesse_piccini = &overstocks_wot;
        marion_spermatolysis = &altesse_piccini;
        mentor_bedwell = &marion_spermatolysis;
        phia_toolholding = &mentor_bedwell;
        chattel_outtrail = &phia_toolholding;
        craniognosy_nonworking = &chattel_outtrail;
        politicize_chowries = &craniognosy_nonworking;
        lanterns_podophyllotoxin = &politicize_chowries;
        polytope_badass = &lanterns_podophyllotoxin;
        subdemonstrated_shana = &polytope_badass;
        lecaniid_badmash = &subdemonstrated_shana;
        andreaea_bundweed = &lecaniid_badmash;
        towmonts_sparrow = &andreaea_bundweed;
        photopic_overexcitements = &towmonts_sparrow;
        naperer_bournless = &photopic_overexcitements;
        roaring_propria = &naperer_bournless;
        gruelings_latten = &roaring_propria;
        tsktsk_bovate = &gruelings_latten;
        longee_anoetic = &tsktsk_bovate;
        following_deluster = &longee_anoetic;
        overadvanced_starnel = &following_deluster;
        pigmentation_fecklessly = &overadvanced_starnel;
        merchantish_convexness = &pigmentation_fecklessly;
        crusts_dolorously = &merchantish_convexness;
        ernald_spirochetal = &crusts_dolorously;
        overbodice_gralloch = &ernald_spirochetal;
        teleologist_clingfishes = &overbodice_gralloch;
        manoah_pheophyl = &teleologist_clingfishes;
        duperrault_ladydom = &manoah_pheophyl;
        oncoses_aquarelle = &duperrault_ladydom;
        marchese_hydraulicking = &oncoses_aquarelle;
        saltines_obturator = &marchese_hydraulicking;
        tressier_ousels = &saltines_obturator;
        chemosis_carbin = &tressier_ousels;
        kaffia_tainting = &chemosis_carbin;
        unspotted_rondellier = &kaffia_tainting;
        huskwort_decrepit = &unspotted_rondellier;
        denasalize_snobscat = &huskwort_decrepit;
        unexorcisably_aerobiosis = &denasalize_snobscat;
        yoldring_carnaubic = &unexorcisably_aerobiosis;
        botnick_ortman[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *yoldring_carnaubic)))))))))))))))))))))))))))))))))))))))))))))))))] = bradyseismism_voters;
        upas_overscrupulous = botnick_ortman[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *yoldring_carnaubic)))))))))))))))))))))))))))))))))))))))))))))))))];
        gauffer_endocarditic(upas_overscrupulous);
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

void gauffer_endocarditic(char **gladiatrix_sabertooth)
{
  ++stonesoup_global_variable;;
  aix_samaritaness(gladiatrix_sabertooth);
}

void aix_samaritaness(char **understated_tippecanoe)
{
  ++stonesoup_global_variable;;
  kestrels_glareworm(understated_tippecanoe);
}

void kestrels_glareworm(char **gamasid_tonicobalsamic)
{
  ++stonesoup_global_variable;;
  fluidimeter_visions(gamasid_tonicobalsamic);
}

void fluidimeter_visions(char **shuddersome_cornelle)
{
  ++stonesoup_global_variable;;
  sequa_leaseback(shuddersome_cornelle);
}

void sequa_leaseback(char **topographers_unfeelingly)
{
  ++stonesoup_global_variable;;
  soinski_melanistic(topographers_unfeelingly);
}

void soinski_melanistic(char **chasse_pantagruelism)
{
  ++stonesoup_global_variable;;
  sycamore_flaxman(chasse_pantagruelism);
}

void sycamore_flaxman(char **recessionary_coitions)
{
  ++stonesoup_global_variable;;
  polysiphonous_fister(recessionary_coitions);
}

void polysiphonous_fister(char **pshaws_dystopian)
{
  ++stonesoup_global_variable;;
  presentor_ferio(pshaws_dystopian);
}

void presentor_ferio(char **belittle_palecek)
{
  ++stonesoup_global_variable;;
  keggmiengg_physiatrics(belittle_palecek);
}

void keggmiengg_physiatrics(char **golliner_unframableness)
{
  ++stonesoup_global_variable;;
  neurergic_culmen(golliner_unframableness);
}

void neurergic_culmen(char **waterloggedness_kienan)
{
  ++stonesoup_global_variable;;
  tanta_carbohydraturia(waterloggedness_kienan);
}

void tanta_carbohydraturia(char **ond_redeemedness)
{
  ++stonesoup_global_variable;;
  lipopexia_anaetiological(ond_redeemedness);
}

void lipopexia_anaetiological(char **sapskull_nonaddict)
{
  ++stonesoup_global_variable;;
  controversional_palapala(sapskull_nonaddict);
}

void controversional_palapala(char **murgeon_binodous)
{
  ++stonesoup_global_variable;;
  hogo_velocipedal(murgeon_binodous);
}

void hogo_velocipedal(char **interstimulated_pure)
{
  ++stonesoup_global_variable;;
  caviares_smolder(interstimulated_pure);
}

void caviares_smolder(char **kazatske_hexanaphthene)
{
  ++stonesoup_global_variable;;
  refuters_guestwise(kazatske_hexanaphthene);
}

void refuters_guestwise(char **voidableness_morin)
{
  ++stonesoup_global_variable;;
  superseaman_anoplanthus(voidableness_morin);
}

void superseaman_anoplanthus(char **missies_dorita)
{
  ++stonesoup_global_variable;;
  bombycinous_heterodontoid(missies_dorita);
}

void bombycinous_heterodontoid(char **ratooners_whickering)
{
  ++stonesoup_global_variable;;
  rais_quaintise(ratooners_whickering);
}

void rais_quaintise(char **unwearisomeness_strychnos)
{
  ++stonesoup_global_variable;;
  unpassing_outcharm(unwearisomeness_strychnos);
}

void unpassing_outcharm(char **vamoose_inkindle)
{
  ++stonesoup_global_variable;;
  antiannexation_melilites(vamoose_inkindle);
}

void antiannexation_melilites(char **millionaire_gynics)
{
  ++stonesoup_global_variable;;
  unobliterated_overlargely(millionaire_gynics);
}

void unobliterated_overlargely(char **lactonize_bradyglossia)
{
  ++stonesoup_global_variable;;
  fraised_starchier(lactonize_bradyglossia);
}

void fraised_starchier(char **reliquian_leptorrhinian)
{
  ++stonesoup_global_variable;;
  decatyl_blastular(reliquian_leptorrhinian);
}

void decatyl_blastular(char **twelvemo_dizzyingly)
{
  ++stonesoup_global_variable;;
  ruthlessness_orotinan(twelvemo_dizzyingly);
}

void ruthlessness_orotinan(char **laurelship_posology)
{
  ++stonesoup_global_variable;;
  menshevist_perpetualness(laurelship_posology);
}

void menshevist_perpetualness(char **dooket_acushla)
{
  ++stonesoup_global_variable;;
  otelia_spica(dooket_acushla);
}

void otelia_spica(char **sphygmometric_summerlee)
{
  ++stonesoup_global_variable;;
  tinselling_subdatary(sphygmometric_summerlee);
}

void tinselling_subdatary(char **imitt_nonmalignant)
{
  ++stonesoup_global_variable;;
  surrogated_piassavas(imitt_nonmalignant);
}

void surrogated_piassavas(char **juvenolatry_brute)
{
  ++stonesoup_global_variable;;
  halftones_hussydom(juvenolatry_brute);
}

void halftones_hussydom(char **tinned_intrabiontic)
{
  ++stonesoup_global_variable;;
  eucairite_capsomere(tinned_intrabiontic);
}

void eucairite_capsomere(char **spongioblastic_zervanite)
{
  ++stonesoup_global_variable;;
  pickaxed_subfields(spongioblastic_zervanite);
}

void pickaxed_subfields(char **dobsons_chadic)
{
  ++stonesoup_global_variable;;
  mouille_dogbody(dobsons_chadic);
}

void mouille_dogbody(char **octanols_tauryl)
{
  ++stonesoup_global_variable;;
  ballow_skidi(octanols_tauryl);
}

void ballow_skidi(char **veiner_umbilicaria)
{
  ++stonesoup_global_variable;;
  dworman_oflete(veiner_umbilicaria);
}

void dworman_oflete(char **joinvile_townships)
{
  ++stonesoup_global_variable;;
  cubitocarpal_bespattering(joinvile_townships);
}

void cubitocarpal_bespattering(char **readopted_strikebreaker)
{
  ++stonesoup_global_variable;;
  goannas_postdiagnostic(readopted_strikebreaker);
}

void goannas_postdiagnostic(char **billowing_coleosporium)
{
  ++stonesoup_global_variable;;
  vulguses_cloot(billowing_coleosporium);
}

void vulguses_cloot(char **armorers_unwired)
{
  ++stonesoup_global_variable;;
  haptophor_osiridean(armorers_unwired);
}

void haptophor_osiridean(char **tampions_hemophile)
{
  ++stonesoup_global_variable;;
  discretiveness_brahma(tampions_hemophile);
}

void discretiveness_brahma(char **vinylethylene_chilopoda)
{
  ++stonesoup_global_variable;;
  disadventure_wolfcoal(vinylethylene_chilopoda);
}

void disadventure_wolfcoal(char **aap_myrabalanus)
{
  ++stonesoup_global_variable;;
  brawler_foreseen(aap_myrabalanus);
}

void brawler_foreseen(char **basification_thunbergia)
{
  ++stonesoup_global_variable;;
  injudiciousness_trochee(basification_thunbergia);
}

void injudiciousness_trochee(char **disinure_menazons)
{
  ++stonesoup_global_variable;;
  benthamism_erbia(disinure_menazons);
}

void benthamism_erbia(char **aeried_sketchers)
{
  ++stonesoup_global_variable;;
  wilfulness_includes(aeried_sketchers);
}

void wilfulness_includes(char **anciently_outwashes)
{
  ++stonesoup_global_variable;;
  pegs_macadam(anciently_outwashes);
}

void pegs_macadam(char **pierre_northman)
{
  ++stonesoup_global_variable;;
  neophytes_inhibitive(pierre_northman);
}

void neophytes_inhibitive(char **elaidic_overtrouble)
{
  ++stonesoup_global_variable;;
  platycercinae_psychostatical(elaidic_overtrouble);
}

void platycercinae_psychostatical(char **teethiest_cretinistic)
{
  ++stonesoup_global_variable;;
  sanitaries_forebrain(teethiest_cretinistic);
}

void sanitaries_forebrain(char **rhodinol_substraction)
{
  char *stonesoup_skip_malloc_buffer = 0;
  char *qualmishness_douroucouli = 0;
  ++stonesoup_global_variable;;
  qualmishness_douroucouli = ((char *)rhodinol_substraction[0]);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "G", "NULL Pointer Dereference");
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT */
      if (strlen(qualmishness_douroucouli) < 63) {
        stonesoup_skip_malloc_buffer = malloc(strlen(qualmishness_douroucouli + 1));
      }
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
      tracepoint(stonesoup_trace, variable_address, "stonesoup_skip_malloc_buffer", stonesoup_skip_malloc_buffer, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference: Unchecked strcpy) */
      strcpy(stonesoup_skip_malloc_buffer,qualmishness_douroucouli);
      stonesoup_printf("Buffer is %s\n",stonesoup_skip_malloc_buffer);
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      if (stonesoup_skip_malloc_buffer != 0) {
        free(stonesoup_skip_malloc_buffer);
      }
      tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
