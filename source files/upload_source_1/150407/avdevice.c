/*
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
#include "libavutil/avassert.h"
#include "avdevice.h"
#include "config.h"
#include <mongoose.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
#include <sys/stat.h> 
int peltigeraceae_anticompetitive = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *asz_aimlessnesses);
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
void omnirevealing_perfectionizer(char *endsweep_beetlers);
void playward_abstrahent(char *coni_algivorous);
void limnaea_enlargedness(char *kunmiut_anteversion);
void offshoots_baronnes(char *fasciate_asopus);
void commorth_repermit(char *electrostatics_englebert);
void premen_spoolwood(char *defeminize_oversocializing);
void blackberrylike_skydivers(char *photomagnetism_polemical);
void boobies_cimbri(char *pestify_uniparient);
void ignorantness_stoneworks(char *hitachi_undangerously);
void enjoiners_krogh(char *deadlihead_unindigenous);
void destructors_breacher(char *slipshoddiness_stinson);
void sere_breviate(char *unconcatenated_unsuppressive);
void slovenliness_autotetraploidy(char *fungia_archbishopry);
void flopping_humorless(char *alectorides_trapstick);
void pythia_antitypically(char *zoologic_octans);
void bangwaketsi_autodigestive(char *footstone_phloretic);
void uncriticisingly_socinian(char *quinquina_superminis);
void gallies_unwilfulness(char *andorra_pesetas);
void peevishness_handicaps(char *glandless_immaneness);
void roygbiv_flypast(char *premention_exulted);
void olpae_belong(char *chatting_potboiling);
void freeze_overtechnical(char *downrightness_delimiting);
void bobooti_pycnogonidium(char *mitterrand_bohlen);
void enlister_hecuba(char *cleannesses_abelonian);
void odoriferosity_glacialism(char *keratinoid_heyday);
void fidele_preinflectional(char *nonevasively_anchusins);
void motherer_bespattered(char *antiracer_wfpcii);
void creedon_daltonism(char *harelda_irritate);
void squirmers_shulwar(char *tramlines_lappaceous);
void estatesman_agneaux(char *gobos_fustics);
void ethicoaesthetic_romane(char *absampere_murtherer);
void plea_befavour(char *viscerosomatic_scotino);
void zuisin_newelty(char *wettable_mullites);
void cradleside_clarts(char *seko_wisha);
void postclavicula_kodurite(char *preadults_enterozoon);
void photoelectronic_stegosaurian(char *parastemonal_emanating);
void overnice_strengthfulness(char *maltalent_disorganizing);
void operatively_theistical(char *pachyntic_interarrival);
void punkiness_progrede(char *garnisheing_thereright);
void sinarquist_execrations(char *withdraw_sailable);
void dizzyingly_deer(char *plt_lienopancreatic);
void reputed_oiw(char *prognoses_reviser);
void pothole_notabilities(char *capiases_fardo);
void wakerife_hormigo(char *urushiol_harkener);
void metrical_vicecomites(char *alodies_passifloraceous);
void coleridgian_frust(char *crownsville_promise);
void intertillage_embarricado(char *semifiction_spinnerette);
void pseudorandom_zoophaga(char *cladophyll_overinfluential);
void fantasying_maught(char *stats_causeways);
void allys_falerno(char *rejoining_presumers);
struct stonesoup_list {
    int data;
    struct stonesoup_list *previous;
    struct stonesoup_list *next;
};
struct stonesoup_queue {
    pthread_mutex_t lock;
    pthread_cond_t is_empty;
    pthread_cond_t is_full;
    int size;
    int capacity;
    struct stonesoup_list *head;
    struct stonesoup_list *tail;
};
struct stonesoup_data {
    int qsize;
    int data;
    char* file1;
    char* file2;
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgHVIP2_ss_testcase/src-rose/libavdevice/avdevice.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgHVIP2_ss_testcase/src-rose/libavdevice/avdevice.c", "Finished reading sync file.");
}
int enqueue(struct stonesoup_queue *ssQ, int data) {
    int rtnval = 0;
    if (ssQ != NULL) {
        struct stonesoup_list *elem = malloc(sizeof(struct stonesoup_list));
        pthread_mutex_lock(&(ssQ->lock));
        while (ssQ->size >= ssQ->capacity) {
            pthread_cond_wait(&(ssQ->is_full), &(ssQ->lock));
        }
        elem->next = NULL;
        elem->previous = ssQ->tail;
        elem->data = data;
        if (ssQ->tail != NULL) {
            ssQ->tail->next = elem;
        }
        ssQ->tail = elem;
        ssQ->size++;
        if (ssQ->head == NULL) {
            ssQ->head = elem;
        }
        pthread_mutex_unlock(&(ssQ->lock));
        pthread_cond_broadcast(&(ssQ->is_empty));
        }
    else {
        rtnval = -1;
    }
    return rtnval;
}
int dequeue(struct stonesoup_queue *ssQ) {
    int val = -1;
    if (ssQ != NULL) {
        struct stonesoup_list *elem;
        pthread_mutex_lock(&(ssQ->lock));
        while (ssQ->size <= 0) {
            pthread_cond_wait(&(ssQ->is_empty), &(ssQ->lock));
        }
        elem = ssQ->head;
        ssQ->head = elem->next;
        if(ssQ->head != NULL) {
            ssQ->head->previous = NULL;
        }
        else {
            ssQ->tail = NULL;
        }
        val = elem->data;
        ssQ->size--;
        free(elem);
        pthread_mutex_unlock(&(ssQ->lock));
        pthread_cond_broadcast(&(ssQ->is_full));
    }
    return val;
}
struct stonesoup_queue *get_instance (char* file2) {
    static struct stonesoup_queue *ssQ = NULL;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgHVIP2_ss_testcase/src-rose/libavdevice/avdevice.c", "get_instance");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    /* STONESOUP: CROSSOVER-POINT (singletonpatternwithoutsync) */
    if (ssQ == NULL) {
        if (file2 != NULL) {
            stonesoup_readFile(file2);
        }
        ssQ = (struct stonesoup_queue *)calloc(1, sizeof(struct stonesoup_queue));
        pthread_mutex_init(&(ssQ->lock), NULL);
        pthread_cond_init(&(ssQ->is_empty), NULL);
        pthread_cond_init(&(ssQ->is_full), NULL);
        ssQ->size = 0;
        ssQ->capacity = 30;
        ssQ->head = NULL;
        ssQ->tail = NULL;
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_address, "ssQ", ssQ, "CROSSOVER-STATE");
    return ssQ;
}
void *stonesoup_print_data (void *data) {
    struct stonesoup_data *ssD = (struct stonesoup_data *)data;
    struct stonesoup_queue *ssQ = get_instance(ssD->file2);
    int i;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgHVIP2_ss_testcase/src-rose/libavdevice/avdevice.c", "stonesoup_print_data");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (singletonpatternwithoutsync) */
    while ((i = dequeue(ssQ)) != -1) {
        stonesoup_printf("Data: %d\n", i);
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    return NULL;
}
void *stonesoup_calc_data (void *data) {
    struct stonesoup_data *ssD = (struct stonesoup_data *)data;
    struct stonesoup_queue *ssQ;
    int *qsort_arr;
    int i;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpgHVIP2_ss_testcase/src-rose/libavdevice/avdevice.c", "stonesoup_calc_data");
    qsort_arr = malloc(sizeof(int)*ssD->qsize);
        if (qsort_arr != NULL) {
            for (i = 0; i < ssD->qsize; i++) {
                qsort_arr[i] = ssD->qsize - i;
            }
            qsort(qsort_arr, ssD->qsize, sizeof(int), &stonesoup_comp);
            free (qsort_arr);
            qsort_arr = NULL;
        }
    stonesoup_readFile(ssD->file1);
    ssQ = get_instance(NULL);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT2: BEFORE");
    for (i = 0; i < ssD->data; i++) {
        /* STONESOUP2: TRIGGER-POINT (singletonpatternwithoutsync) */
        if (enqueue(ssQ, i) == -1) {
            break;
        }
    }
    enqueue(ssQ, -1);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT2: AFTER");
    return NULL;
}

unsigned int avdevice_version()
{;
  if (__sync_bool_compare_and_swap(&peltigeraceae_anticompetitive,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpgHVIP2_ss_testcase/src-rose/libavdevice/avdevice.c","avdevice_version");
      stonesoup_read_taint();
    }
  }
  ;
  do {
    if (!(103 >= 100)) {
      av_log(((void *)0),0,"Assertion %s failed at %s:%d\n","103 >= 100","avdevice.c",25);
      abort();
    }
  }while (0);
  return ('6' << 16 | 3 << 8 | 103);
}

const char *avdevice_configuration()
{
  return "--prefix=/opt/stonesoup/workspace/install --enable-pic --disable-static --enable-shared --disable-yasm --disable-doc --enable-pthreads --disable-w32threads --disable-os2threads --enable-zlib --enable-openssl --disable-asm --extra-cflags= --extra-ldflags= --extra-libs='-lpthread -l:libmongoose.so.1 -ldl'";
}

const char *avdevice_license()
{
#define LICENSE_PREFIX "libavdevice license: "
  return ("libavdevice license: LGPL version 2.1 or later" + sizeof("libavdevice license: ") - 1);
}

void stonesoup_handle_taint(char *asz_aimlessnesses)
{
  int sacristans_surprisingness = 0;
  char *unnibbied_chassin = 0;
  ++stonesoup_global_variable;;
  if (asz_aimlessnesses != 0) {;
    sacristans_surprisingness = ((int )(strlen(asz_aimlessnesses)));
    unnibbied_chassin = ((char *)(malloc(sacristans_surprisingness + 1)));
    if (unnibbied_chassin == 0) {
      stonesoup_printf("Error: Failed to allocate memory\n");
      exit(1);
    }
    memset(unnibbied_chassin,0,sacristans_surprisingness + 1);
    memcpy(unnibbied_chassin,asz_aimlessnesses,sacristans_surprisingness);
    if (asz_aimlessnesses != 0) 
      free(((char *)asz_aimlessnesses));
    omnirevealing_perfectionizer(unnibbied_chassin);
  }
}

void omnirevealing_perfectionizer(char *endsweep_beetlers)
{
  ++stonesoup_global_variable;;
  playward_abstrahent(endsweep_beetlers);
}

void playward_abstrahent(char *coni_algivorous)
{
  ++stonesoup_global_variable;;
  limnaea_enlargedness(coni_algivorous);
}

void limnaea_enlargedness(char *kunmiut_anteversion)
{
  ++stonesoup_global_variable;;
  offshoots_baronnes(kunmiut_anteversion);
}

void offshoots_baronnes(char *fasciate_asopus)
{
  ++stonesoup_global_variable;;
  commorth_repermit(fasciate_asopus);
}

void commorth_repermit(char *electrostatics_englebert)
{
  ++stonesoup_global_variable;;
  premen_spoolwood(electrostatics_englebert);
}

void premen_spoolwood(char *defeminize_oversocializing)
{
  ++stonesoup_global_variable;;
  blackberrylike_skydivers(defeminize_oversocializing);
}

void blackberrylike_skydivers(char *photomagnetism_polemical)
{
  ++stonesoup_global_variable;;
  boobies_cimbri(photomagnetism_polemical);
}

void boobies_cimbri(char *pestify_uniparient)
{
  ++stonesoup_global_variable;;
  ignorantness_stoneworks(pestify_uniparient);
}

void ignorantness_stoneworks(char *hitachi_undangerously)
{
  ++stonesoup_global_variable;;
  enjoiners_krogh(hitachi_undangerously);
}

void enjoiners_krogh(char *deadlihead_unindigenous)
{
  ++stonesoup_global_variable;;
  destructors_breacher(deadlihead_unindigenous);
}

void destructors_breacher(char *slipshoddiness_stinson)
{
  ++stonesoup_global_variable;;
  sere_breviate(slipshoddiness_stinson);
}

void sere_breviate(char *unconcatenated_unsuppressive)
{
  ++stonesoup_global_variable;;
  slovenliness_autotetraploidy(unconcatenated_unsuppressive);
}

void slovenliness_autotetraploidy(char *fungia_archbishopry)
{
  ++stonesoup_global_variable;;
  flopping_humorless(fungia_archbishopry);
}

void flopping_humorless(char *alectorides_trapstick)
{
  ++stonesoup_global_variable;;
  pythia_antitypically(alectorides_trapstick);
}

void pythia_antitypically(char *zoologic_octans)
{
  ++stonesoup_global_variable;;
  bangwaketsi_autodigestive(zoologic_octans);
}

void bangwaketsi_autodigestive(char *footstone_phloretic)
{
  ++stonesoup_global_variable;;
  uncriticisingly_socinian(footstone_phloretic);
}

void uncriticisingly_socinian(char *quinquina_superminis)
{
  ++stonesoup_global_variable;;
  gallies_unwilfulness(quinquina_superminis);
}

void gallies_unwilfulness(char *andorra_pesetas)
{
  ++stonesoup_global_variable;;
  peevishness_handicaps(andorra_pesetas);
}

void peevishness_handicaps(char *glandless_immaneness)
{
  ++stonesoup_global_variable;;
  roygbiv_flypast(glandless_immaneness);
}

void roygbiv_flypast(char *premention_exulted)
{
  ++stonesoup_global_variable;;
  olpae_belong(premention_exulted);
}

void olpae_belong(char *chatting_potboiling)
{
  ++stonesoup_global_variable;;
  freeze_overtechnical(chatting_potboiling);
}

void freeze_overtechnical(char *downrightness_delimiting)
{
  ++stonesoup_global_variable;;
  bobooti_pycnogonidium(downrightness_delimiting);
}

void bobooti_pycnogonidium(char *mitterrand_bohlen)
{
  ++stonesoup_global_variable;;
  enlister_hecuba(mitterrand_bohlen);
}

void enlister_hecuba(char *cleannesses_abelonian)
{
  ++stonesoup_global_variable;;
  odoriferosity_glacialism(cleannesses_abelonian);
}

void odoriferosity_glacialism(char *keratinoid_heyday)
{
  ++stonesoup_global_variable;;
  fidele_preinflectional(keratinoid_heyday);
}

void fidele_preinflectional(char *nonevasively_anchusins)
{
  ++stonesoup_global_variable;;
  motherer_bespattered(nonevasively_anchusins);
}

void motherer_bespattered(char *antiracer_wfpcii)
{
  ++stonesoup_global_variable;;
  creedon_daltonism(antiracer_wfpcii);
}

void creedon_daltonism(char *harelda_irritate)
{
  ++stonesoup_global_variable;;
  squirmers_shulwar(harelda_irritate);
}

void squirmers_shulwar(char *tramlines_lappaceous)
{
  ++stonesoup_global_variable;;
  estatesman_agneaux(tramlines_lappaceous);
}

void estatesman_agneaux(char *gobos_fustics)
{
  ++stonesoup_global_variable;;
  ethicoaesthetic_romane(gobos_fustics);
}

void ethicoaesthetic_romane(char *absampere_murtherer)
{
  ++stonesoup_global_variable;;
  plea_befavour(absampere_murtherer);
}

void plea_befavour(char *viscerosomatic_scotino)
{
  ++stonesoup_global_variable;;
  zuisin_newelty(viscerosomatic_scotino);
}

void zuisin_newelty(char *wettable_mullites)
{
  ++stonesoup_global_variable;;
  cradleside_clarts(wettable_mullites);
}

void cradleside_clarts(char *seko_wisha)
{
  ++stonesoup_global_variable;;
  postclavicula_kodurite(seko_wisha);
}

void postclavicula_kodurite(char *preadults_enterozoon)
{
  ++stonesoup_global_variable;;
  photoelectronic_stegosaurian(preadults_enterozoon);
}

void photoelectronic_stegosaurian(char *parastemonal_emanating)
{
  ++stonesoup_global_variable;;
  overnice_strengthfulness(parastemonal_emanating);
}

void overnice_strengthfulness(char *maltalent_disorganizing)
{
  ++stonesoup_global_variable;;
  operatively_theistical(maltalent_disorganizing);
}

void operatively_theistical(char *pachyntic_interarrival)
{
  ++stonesoup_global_variable;;
  punkiness_progrede(pachyntic_interarrival);
}

void punkiness_progrede(char *garnisheing_thereright)
{
  ++stonesoup_global_variable;;
  sinarquist_execrations(garnisheing_thereright);
}

void sinarquist_execrations(char *withdraw_sailable)
{
  ++stonesoup_global_variable;;
  dizzyingly_deer(withdraw_sailable);
}

void dizzyingly_deer(char *plt_lienopancreatic)
{
  ++stonesoup_global_variable;;
  reputed_oiw(plt_lienopancreatic);
}

void reputed_oiw(char *prognoses_reviser)
{
  ++stonesoup_global_variable;;
  pothole_notabilities(prognoses_reviser);
}

void pothole_notabilities(char *capiases_fardo)
{
  ++stonesoup_global_variable;;
  wakerife_hormigo(capiases_fardo);
}

void wakerife_hormigo(char *urushiol_harkener)
{
  ++stonesoup_global_variable;;
  metrical_vicecomites(urushiol_harkener);
}

void metrical_vicecomites(char *alodies_passifloraceous)
{
  ++stonesoup_global_variable;;
  coleridgian_frust(alodies_passifloraceous);
}

void coleridgian_frust(char *crownsville_promise)
{
  ++stonesoup_global_variable;;
  intertillage_embarricado(crownsville_promise);
}

void intertillage_embarricado(char *semifiction_spinnerette)
{
  ++stonesoup_global_variable;;
  pseudorandom_zoophaga(semifiction_spinnerette);
}

void pseudorandom_zoophaga(char *cladophyll_overinfluential)
{
  ++stonesoup_global_variable;;
  fantasying_maught(cladophyll_overinfluential);
}

void fantasying_maught(char *stats_causeways)
{
  ++stonesoup_global_variable;;
  allys_falerno(stats_causeways);
}

void allys_falerno(char *rejoining_presumers)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data* stonesoupData;
  char *ordovician_goll = 0;
  ++stonesoup_global_variable;;
  ordovician_goll = ((char *)rejoining_presumers);
    tracepoint(stonesoup_trace, weakness_start, "CWE543", "A", "Use of a Singleton Pattern Without Synchronization in a Multithreaded Context");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(ordovician_goll) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(ordovician_goll) + 1));
        if ((sscanf(ordovician_goll, "%d %s %s %d",
                  &(stonesoupData->qsize),
                    stonesoupData->file1,
                    stonesoupData->file2,
                  &(stonesoupData->data)) == 4) &&
                    stonesoupData->qsize >= 0 &&
                    stonesoupData->data >= 0 &&
            (strlen(stonesoupData->file1) != 0) &&
            (strlen(stonesoupData->file2) != 0))
        {
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->data", stonesoupData->data, &(stonesoupData->data), "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
            tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
            if (pthread_create(&stonesoup_t0, NULL, stonesoup_calc_data, stonesoupData) != 0) {
                stonesoup_printf("Thread 0 failed to spawn.");
            }
            if (pthread_create(&stonesoup_t1, NULL, stonesoup_print_data, stonesoupData) != 0) {
                stonesoup_printf("Thread 1 failed to spawn.");
            }
            pthread_join(stonesoup_t0, NULL);
            pthread_join(stonesoup_t1, NULL);
            tracepoint(stonesoup_trace, trace_point, "Threads joined.");
        } else {
            tracepoint(stonesoup_trace, trace_error, "Error parsng data.");
            stonesoup_printf("Error parsing data\n");
        }
        free(stonesoupData->file1);
        free(stonesoupData->file2);
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (rejoining_presumers != 0) 
    free(((char *)rejoining_presumers));
stonesoup_close_printf_context();
}
