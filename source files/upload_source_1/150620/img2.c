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
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <sys/types.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
typedef struct {
enum AVCodecID id;
const char *str;}IdStrMap;
static const IdStrMap img_tags[] = {{(AV_CODEC_ID_MJPEG), ("jpeg")}, {(AV_CODEC_ID_MJPEG), ("jpg")}, {(AV_CODEC_ID_MJPEG), ("jps")}, {(AV_CODEC_ID_LJPEG), ("ljpg")}, {(AV_CODEC_ID_JPEGLS), ("jls")}, {(AV_CODEC_ID_PNG), ("png")}, {(AV_CODEC_ID_PNG), ("pns")}, {(AV_CODEC_ID_PNG), ("mng")}, {(AV_CODEC_ID_PPM), ("ppm")}, {(AV_CODEC_ID_PPM), ("pnm")}, {(AV_CODEC_ID_PGM), ("pgm")}, {(AV_CODEC_ID_PGMYUV), ("pgmyuv")}, {(AV_CODEC_ID_PBM), ("pbm")}, {(AV_CODEC_ID_PAM), ("pam")}, {(AV_CODEC_ID_MPEG1VIDEO), ("mpg1-img")}, {(AV_CODEC_ID_MPEG2VIDEO), ("mpg2-img")}, {(AV_CODEC_ID_MPEG4), ("mpg4-img")}, {(AV_CODEC_ID_FFV1), ("ffv1-img")}, {(AV_CODEC_ID_RAWVIDEO), ("y")}, {(AV_CODEC_ID_RAWVIDEO), ("raw")}, {(AV_CODEC_ID_BMP), ("bmp")}, {(AV_CODEC_ID_GIF), ("gif")}, {(AV_CODEC_ID_TARGA), ("tga")}, {(AV_CODEC_ID_TIFF), ("tiff")}, {(AV_CODEC_ID_TIFF), ("tif")}, {(AV_CODEC_ID_SGI), ("sgi")}, {(AV_CODEC_ID_PTX), ("ptx")}, {(AV_CODEC_ID_PCX), ("pcx")}, {(AV_CODEC_ID_BRENDER_PIX), ("pix")}, {(AV_CODEC_ID_SUNRAST), ("sun")}, {(AV_CODEC_ID_SUNRAST), ("ras")}, {(AV_CODEC_ID_SUNRAST), ("rs")}, {(AV_CODEC_ID_SUNRAST), ("im1")}, {(AV_CODEC_ID_SUNRAST), ("im8")}, {(AV_CODEC_ID_SUNRAST), ("im24")}, {(AV_CODEC_ID_SUNRAST), ("im32")}, {(AV_CODEC_ID_SUNRAST), ("sunras")}, {(AV_CODEC_ID_JPEG2000), ("j2c")}, {(AV_CODEC_ID_JPEG2000), ("j2k")}, {(AV_CODEC_ID_JPEG2000), ("jp2")}, {(AV_CODEC_ID_JPEG2000), ("jpc")}, {(AV_CODEC_ID_DPX), ("dpx")}, {(AV_CODEC_ID_EXR), ("exr")}, {(AV_CODEC_ID_PICTOR), ("pic")}, {(AV_CODEC_ID_V210X), ("yuv10")}, {(AV_CODEC_ID_XBM), ("xbm")}, {(AV_CODEC_ID_XFACE), ("xface")}, {(AV_CODEC_ID_XWD), ("xwd")}, {(AV_CODEC_ID_NONE), (((void *)0))}};
int caudiform_nearside = 0;
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpco7yfF_ss_testcase/src-rose/libavformat/img2.c", "stonesoup_readFile");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpco7yfF_ss_testcase/src-rose/libavformat/img2.c", "calcIncamount");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpco7yfF_ss_testcase/src-rose/libavformat/img2.c", "toPound");
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

static enum AVCodecID av_str2id(const IdStrMap *tags,const char *str)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data *dataStruct = malloc(sizeof(struct stonesoup_data));
  char *spillbox_smitt = 0;
  int valerians_microcolumnar;
  int refractures_gene;
  char *endothoracic_barmiest = 0;
  int **************************************************muffy_giavani = 0;
  int *************************************************underbury_junks = 0;
  int ************************************************euglenaceae_briquette = 0;
  int ***********************************************biflex_monoureide = 0;
  int **********************************************alphonsism_tsaritza = 0;
  int *********************************************saulie_funerate = 0;
  int ********************************************turbination_ambusher = 0;
  int *******************************************carshops_misinforming = 0;
  int ******************************************alnage_pegmatite = 0;
  int *****************************************aromatophor_ruinable = 0;
  int ****************************************apotheose_disappointment = 0;
  int ***************************************hypotype_tomfooleries = 0;
  int **************************************silenter_priddy = 0;
  int *************************************plumatelloid_baldpatedness = 0;
  int ************************************tremain_slither = 0;
  int ***********************************brachialis_bloubiskop = 0;
  int **********************************undebased_pacien = 0;
  int *********************************phaethonic_rakishly = 0;
  int ********************************lurcher_qnp = 0;
  int *******************************indefensibility_kolarian = 0;
  int ******************************protovestiary_argentina = 0;
  int *****************************pharmacopolist_toxiinfectious = 0;
  int ****************************philhippic_squatty = 0;
  int ***************************sart_soviets = 0;
  int **************************binodous_sirenize = 0;
  int *************************himene_allotropicity = 0;
  int ************************neoparaffin_formalise = 0;
  int ***********************cedarbrook_bohea = 0;
  int **********************decoctible_redemonstration = 0;
  int *********************mariette_bipinnatisected = 0;
  int ********************embayed_huskers = 0;
  int *******************beraking_athodyd = 0;
  int ******************notothere_doerun = 0;
  int *****************sansom_queernesses = 0;
  int ****************hedges_chrysanthemum = 0;
  int ***************candescent_pultaceous = 0;
  int **************oscarellidae_gaeing = 0;
  int *************unwading_tulkepaia = 0;
  int ************magalensia_mattoir = 0;
  int ***********synopsis_curse = 0;
  int **********adulterate_dinuba = 0;
  int *********gasworker_gastonville = 0;
  int ********mercatoria_sirenomelus = 0;
  int *******mushes_sluff = 0;
  int ******vitalizing_bocage = 0;
  int *****theeked_didymitis = 0;
  int ****bicarbureted_stimulate = 0;
  int ***propenols_apetalae = 0;
  int **chaochowfu_minenwerfer = 0;
  int *cardinalfish_tregerg = 0;
  int deprecators_takyr;
  char *blennophlogisma_insubmergible[10] = {0};
  int laniiform_crackbrained = 0;
  char *unmusical_witted = 0;
  int sldney_lorriker = 149;
  char *bavarian_zanyism;;
  if (__sync_bool_compare_and_swap(&caudiform_nearside,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpco7yfF_ss_testcase/src-rose/libavformat/img2.c","av_str2id");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&bavarian_zanyism,"3397",sldney_lorriker);
      if (bavarian_zanyism != 0) {;
        laniiform_crackbrained = ((int )(strlen(bavarian_zanyism)));
        unmusical_witted = ((char *)(malloc(laniiform_crackbrained + 1)));
        if (unmusical_witted == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(unmusical_witted,0,laniiform_crackbrained + 1);
        memcpy(unmusical_witted,bavarian_zanyism,laniiform_crackbrained);
        if (bavarian_zanyism != 0) 
          free(((char *)bavarian_zanyism));
        deprecators_takyr = 5;
        cardinalfish_tregerg = &deprecators_takyr;
        chaochowfu_minenwerfer = &cardinalfish_tregerg;
        propenols_apetalae = &chaochowfu_minenwerfer;
        bicarbureted_stimulate = &propenols_apetalae;
        theeked_didymitis = &bicarbureted_stimulate;
        vitalizing_bocage = &theeked_didymitis;
        mushes_sluff = &vitalizing_bocage;
        mercatoria_sirenomelus = &mushes_sluff;
        gasworker_gastonville = &mercatoria_sirenomelus;
        adulterate_dinuba = &gasworker_gastonville;
        synopsis_curse = &adulterate_dinuba;
        magalensia_mattoir = &synopsis_curse;
        unwading_tulkepaia = &magalensia_mattoir;
        oscarellidae_gaeing = &unwading_tulkepaia;
        candescent_pultaceous = &oscarellidae_gaeing;
        hedges_chrysanthemum = &candescent_pultaceous;
        sansom_queernesses = &hedges_chrysanthemum;
        notothere_doerun = &sansom_queernesses;
        beraking_athodyd = &notothere_doerun;
        embayed_huskers = &beraking_athodyd;
        mariette_bipinnatisected = &embayed_huskers;
        decoctible_redemonstration = &mariette_bipinnatisected;
        cedarbrook_bohea = &decoctible_redemonstration;
        neoparaffin_formalise = &cedarbrook_bohea;
        himene_allotropicity = &neoparaffin_formalise;
        binodous_sirenize = &himene_allotropicity;
        sart_soviets = &binodous_sirenize;
        philhippic_squatty = &sart_soviets;
        pharmacopolist_toxiinfectious = &philhippic_squatty;
        protovestiary_argentina = &pharmacopolist_toxiinfectious;
        indefensibility_kolarian = &protovestiary_argentina;
        lurcher_qnp = &indefensibility_kolarian;
        phaethonic_rakishly = &lurcher_qnp;
        undebased_pacien = &phaethonic_rakishly;
        brachialis_bloubiskop = &undebased_pacien;
        tremain_slither = &brachialis_bloubiskop;
        plumatelloid_baldpatedness = &tremain_slither;
        silenter_priddy = &plumatelloid_baldpatedness;
        hypotype_tomfooleries = &silenter_priddy;
        apotheose_disappointment = &hypotype_tomfooleries;
        aromatophor_ruinable = &apotheose_disappointment;
        alnage_pegmatite = &aromatophor_ruinable;
        carshops_misinforming = &alnage_pegmatite;
        turbination_ambusher = &carshops_misinforming;
        saulie_funerate = &turbination_ambusher;
        alphonsism_tsaritza = &saulie_funerate;
        biflex_monoureide = &alphonsism_tsaritza;
        euglenaceae_briquette = &biflex_monoureide;
        underbury_junks = &euglenaceae_briquette;
        muffy_giavani = &underbury_junks;
        blennophlogisma_insubmergible[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *muffy_giavani)))))))))))))))))))))))))))))))))))))))))))))))))] = unmusical_witted;
        endothoracic_barmiest = blennophlogisma_insubmergible[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *muffy_giavani)))))))))))))))))))))))))))))))))))))))))))))))))];
        refractures_gene = 5;
        while(1 == 1){
          refractures_gene = refractures_gene * 2;
          refractures_gene = refractures_gene + 2;
          if (refractures_gene > 1000) {
            break; 
          }
        }
        valerians_microcolumnar = refractures_gene;
        spillbox_smitt = ((char *)endothoracic_barmiest);
    tracepoint(stonesoup_trace, weakness_start, "CWE820", "A", "Missing Synchronization");
    if (dataStruct) {
        dataStruct->inc_amount = 1;
        dataStruct->data = malloc(sizeof(char) * (strlen(spillbox_smitt) + 1));
        dataStruct->file1 = malloc(sizeof(char) * (strlen(spillbox_smitt) + 1));
        dataStruct->file2 = malloc(sizeof(char) * (strlen(spillbox_smitt) + 1));
        if (dataStruct->data) {
            if ((sscanf(spillbox_smitt, "%d %s %s %s",
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
        if (endothoracic_barmiest != 0) 
          free(((char *)endothoracic_barmiest));
stonesoup_close_printf_context();
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
