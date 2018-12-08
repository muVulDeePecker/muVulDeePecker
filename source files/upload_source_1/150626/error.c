/* error.c:  common exception handling for Subversion
 *
 * ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */
#include <stdarg.h>
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <zlib.h>
#ifndef SVN_ERR__TRACING
#define SVN_ERR__TRACING
#endif
#include "svn_cmdline.h"
#include "svn_error.h"
#include "svn_pools.h"
#include "svn_utf.h"
#ifdef SVN_DEBUG
/* XXX FIXME: These should be protected by a thread mutex.
   svn_error__locate and make_error_internal should cooperate
   in locking and unlocking it. */
/* XXX TODO: Define mutex here #if APR_HAS_THREADS */
/* file_line for the non-debug case. */
#endif /* SVN_DEBUG */
#include "svn_private_config.h"
#include "private/svn_error_private.h"
/*
 * Undefine the helpers for creating errors.
 *
 * *NOTE*: Any use of these functions in any other function may need
 * to call svn_error__locate() because the macro that would otherwise
 * do this is being undefined and the filename and line number will
 * not be properly set in the static error_file and error_line
 * variables.
 */
#undef svn_error_create
#undef svn_error_createf
#undef svn_error_quick_wrap
#undef svn_error_wrap_apr
/* Note: Although this is a "__" function, it was historically in the
 * public ABI, so we can never change it or remove its signature, even
 * though it is now only used in SVN_DEBUG mode. */
#include <sys/stat.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
#include <semaphore.h> 
int joggers_amylodyspepsia = 0;
int stonesoup_global_variable;

union monocarps_brickset 
{
  char *pollists_opportunely;
  double fibrointestinal_scillain;
  char *bursautee_capulet;
  char birrotch_centauromachia;
  int formulas_diyarbakir;
}
;
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
void phyllite_achimenes(union monocarps_brickset *cargian_dolent);
void heterometaboly_eucosia(union monocarps_brickset *esdud_subcurate);
void toping_cephen(union monocarps_brickset *johnnie_ergates);
void frized_undividably(union monocarps_brickset *myectomize_pachypod);
void preoccupate_bordman(union monocarps_brickset *pearmain_absolvable);
void adelheid_veszelyite(union monocarps_brickset *gobbin_epikleses);
void shirtless_mediatorship(union monocarps_brickset *eniac_reingratiate);
void wifedoms_leupold(union monocarps_brickset *vichyssoise_steamerload);
void onlay_unwhole(union monocarps_brickset *ungenteely_surat);
void unrejoicing_floriated(union monocarps_brickset *disdainable_dochmii);
void stanniferous_conjunctival(union monocarps_brickset *blepharotomy_friskers);
void zmudz_spumoid(union monocarps_brickset *sidelock_wakiki);
void grayfly_tramells(union monocarps_brickset *myctophidae_juliennes);
void ichthyopolist_cwierc(union monocarps_brickset *hagiographist_familial);
void chantment_mentor(union monocarps_brickset *nonstaining_preconized);
void shathmont_boarhound(union monocarps_brickset *sprawliest_amphibiontic);
void gleaning_bereave(union monocarps_brickset *gleeks_cassian);
void yucaipa_heteroside(union monocarps_brickset *rifs_chammies);
void unendeared_liss(union monocarps_brickset *coagulative_nemichthys);
void erek_theria(union monocarps_brickset *stepdancing_animetta);
void disenthronement_babbitt(union monocarps_brickset *inventibility_barotrauma);
void enargite_serosa(union monocarps_brickset *pereskia_jimmyweed);
void cofeature_cyanogens(union monocarps_brickset *heralding_antichurchian);
void pangenic_repace(union monocarps_brickset *lunier_linalools);
void aku_vallisneriaceae(union monocarps_brickset *stictidaceae_ashburnham);
void tishiya_fabiform(union monocarps_brickset *egadi_trent);
void garmenting_photolyze(union monocarps_brickset *helotes_becker);
void misliker_kafir(union monocarps_brickset *ghalva_watches);
void unsewed_coccic(union monocarps_brickset *unincinerated_buildress);
void enteroptotic_gos(union monocarps_brickset *hostile_tinselling);
void pracharak_endplates(union monocarps_brickset *impinger_bewwept);
void dicynodontia_unmistakable(union monocarps_brickset *recesses_tompkinsville);
void mofw_misprision(union monocarps_brickset *krusenstern_corner);
void drowsiest_tepomporize(union monocarps_brickset *nonclamorous_unindoctrinated);
void brume_sourdeline(union monocarps_brickset *servitors_rider);
void patty_beowawe(union monocarps_brickset *paki_heterocaryotic);
void circumgyratory_gammaridae(union monocarps_brickset *nonlevulose_ansgarius);
void allegheny_predespond(union monocarps_brickset *underpresence_gleeting);
void procolonial_noncumbrous(union monocarps_brickset *aerobium_tungstens);
void acetylsalicylic_depravers(union monocarps_brickset *sphenographic_marling);
void waistcoateer_exchanger(union monocarps_brickset *semicordate_chooses);
void yeuks_assimilatory(union monocarps_brickset *precompulsion_unlitigated);
void fetichry_abiology(union monocarps_brickset *oligohemia_habituation);
void postproduction_aslaver(union monocarps_brickset *malleating_sheepstealing);
void rollicker_tariff(union monocarps_brickset *archest_hotdogs);
void frgs_eastleigh(union monocarps_brickset *passifloraceous_mrem);
void strang_lipectomy(union monocarps_brickset *skywrote_fervors);
void deedbote_jeffersonians(union monocarps_brickset *anil_denmark);
void pyromeconic_semifictional(union monocarps_brickset *hedwiga_penal);
void cointension_malagasy(union monocarps_brickset *logia_precelebration);
struct stonesoup_data {
    int qsize;
    char *file1;
    char *file2;
    char *data;
    int data_size;
};
pthread_t stonesoup_t0, stonesoup_t1;
sem_t stonesoup_sem;
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpnz5Y14_ss_testcase/src-rose/subversion/libsvn_subr/error.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
}
void *to1337(void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int qsize;
    int random;
    char temp;
    char *temp_str;
    int i = 0;
    int *stonesoup_arr;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpnz5Y14_ss_testcase/src-rose/subversion/libsvn_subr/error.c", "to1337");
    stonesoup_printf("Entering to1337\n");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int)*stonesoupData->qsize);
    if (stonesoup_arr != NULL) {
        for (i = 0; i < stonesoupData->qsize; i++) {
            stonesoup_arr[i] = stonesoupData->qsize - i;
        }
        qsort(stonesoup_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
        free (stonesoup_arr);
        stonesoup_arr = NULL;
    }
    temp_str = malloc(sizeof(char)*(stonesoupData->data_size + 1));
    qsize = stonesoupData->qsize;
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "to1337: Locking semaphore");
    sem_wait(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "to1337: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Locked semaphore");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        random = (int)(rand() / (double)RAND_MAX + 0.5); /* add .5 before truncation to round */
        switch(stonesoupData->data[i]) { /* 1337 s<r1p7 i5 f0r h4x0r5 */
            case 'c':
                if (random == 0)
                    temp = '<';
                else
                    temp = 'c';
                break;
            case 'e':
                if (random == 0)
                    temp = '3';
                else
                    temp = 'e';
                break;
            case 'i':
                if (random == 0)
                    temp = '1';
                else
                    temp = 'i';
                break;
            case 'l':
                if (random == 0)
                    temp = '1';
                else
                    temp = 'l';
                break;
            case 'o':
                if (random == 0)
                    temp = '0';
                else
                    temp = 'o';
                break;
            case 's':
                if (random == 0)
                    temp = '5';
                else
                    temp = 's';
                break;
            case 't':
                if (random == 0)
                    temp = '7';
                else
                    temp = 't';
                break;
            default:
                temp = stonesoupData->data[i];
                break;
        }
        temp_str[i] = temp;
        i++;
    }
    temp_str[i] = '\0';
    free(stonesoupData->data);
    stonesoupData->data = NULL; /* setting free()'d ptrs to null is good practice yo */
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: SET");
    stonesoup_printf("Set ptr to null\n");
    tracepoint(stonesoup_trace, trace_point, "to1337: Reading file");
    /* execute second */
    stonesoup_readFile(stonesoupData->file2);
    tracepoint(stonesoup_trace, trace_point, "to1337: Read file");
    stonesoup_printf("Set ptr to NON null\n");
    stonesoupData->data = temp_str;
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: UNSET");
    tracepoint(stonesoup_trace, trace_point, "to1337: Unlocking semaphore");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "to1337: Unlocked semaphore");
    tracepoint(stonesoup_trace, trace_point, "to1337: Unlocked semaphore");
    return NULL;
}
void *reverseStr(void * data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int i = 0;
    char *temp_str;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpnz5Y14_ss_testcase/src-rose/subversion/libsvn_subr/error.c", "reverseStr");
    stonesoup_printf("Entering reverseStr\n");
    /* execute first */
    stonesoup_readFile(stonesoupData->file1);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Locking semaphore");
    sem_wait(&stonesoup_sem); /* if weakness has been triggered, */
                                                                    /* too many resource copies available */
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Locked semaphore");
    temp_str = malloc(sizeof(char)* (stonesoupData->data_size + 1));
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_address, "stonesoupData->data", stonesoupData->data, "TRIGGER-STATE: ACCESS");
    for (i = 0; i < stonesoupData->data_size; i++) {
        /* STONESOUP: TRIGGER-POINT (multipleunlocks) */
        stonesoup_printf("Dereferencing ptr\n");
        temp_str[stonesoupData->data_size - 1 - i] = stonesoupData->data[i]; /* null ptr dereference */
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    temp_str[stonesoupData->data_size] = '\0';
    free(stonesoupData->data);
    stonesoupData->data = NULL;
    stonesoupData->data = temp_str;
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Unlocking semaphore");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "reverseStr: Unlocked semaphore");
    tracepoint(stonesoup_trace, trace_point, "reverseStr: Unlocked semaphore");
    return NULL;
}
void toLower (struct stonesoup_data * stonesoupData) {
    int i = 0;
    int semValue = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpnz5Y14_ss_testcase/src-rose/subversion/libsvn_subr/error.c", "toLower");
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Locking semaphore");
    tracepoint(stonesoup_trace, trace_point, "toLower: Locking semaphore");
    sem_wait(&stonesoup_sem);
    stonesoup_printf("Entering toLower\n");
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, trace_point, "toLower: Locked semaphore");
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Locked semaphore");
    for (i = 0; i < strlen(stonesoupData->data) - 1; i++) { /* all caps to lower */
        if (stonesoupData->data[i] >= 'A' &&
            stonesoupData->data[i] <= 'Z') {
            stonesoupData->data[i] += 32;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocking semaphore (01)");
    sem_post(&stonesoup_sem);
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Unlocked semaphore (01)");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocked semaphore (01)");
    tracepoint(stonesoup_trace, trace_point, "toLower: CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocking semaphore (02)");
    /* STONESOUP: CROSSOVER-POINT (multipleunlocks) */
    sem_post(&stonesoup_sem); /* oops, extra unlock */
    sem_getvalue(&stonesoup_sem, &semValue);
    tracepoint(stonesoup_trace, variable_signed_integral, "semaphore", semValue, &semValue, "toLower: Unlocked semaphore (02)");
    tracepoint(stonesoup_trace, trace_point, "toLower: Unlocked semaphore (02)");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "CROSSOVER-STATE");
}

void svn_error__locate(const char *file,long line)
{
#if defined(SVN_DEBUG)
/* XXX TODO: Lock mutex here */
#endif
}
/* Cleanup function for errors.  svn_error_clear () removes this so
   errors that are properly handled *don't* hit this code. */
#if defined(SVN_DEBUG)
/* For easy viewing in a debugger */
/* Fake a use for the variable to avoid compiler warnings */
#endif

static svn_error_t *make_error_internal(apr_status_t apr_err,svn_error_t *child)
{
  apr_pool_t *pool;
  svn_error_t *new_error;
/* Reuse the child's pool, or create our own. */
  if (child) {
    pool = child -> pool;
  }
  else {
    if (apr_pool_create_ex(&pool,((void *)0),((void *)0),((void *)0))) {
      abort();
    }
  }
/* Create the new error structure */
  new_error = (memset(apr_palloc(pool,sizeof(( *new_error))),0,sizeof(( *new_error))));
/* Fill 'er up. */
  new_error -> apr_err = apr_err;
  new_error -> child = child;
  new_error -> pool = pool;
#if defined(SVN_DEBUG)
/* XXX TODO: Unlock mutex here */
#endif
  return new_error;
}
/*** Creating and destroying errors. ***/

svn_error_t *svn_error_create(apr_status_t apr_err,svn_error_t *child,const char *message)
{
  svn_error_t *err;
  err = make_error_internal(apr_err,child);
  if (message) {
    err -> message = (apr_pstrdup(err -> pool,message));
  }
  return err;
}

svn_error_t *svn_error_createf(apr_status_t apr_err,svn_error_t *child,const char *fmt,... )
{
  svn_error_t *err;
  va_list ap;
  err = make_error_internal(apr_err,child);
  __builtin_va_start(ap,fmt);
  err -> message = (apr_pvsprintf(err -> pool,fmt,ap));
  __builtin_va_end(ap);
  return err;
}

svn_error_t *svn_error_wrap_apr(apr_status_t status,const char *fmt,... )
{
  int bagatine_pollarded;
  union monocarps_brickset *cyanhidrosis_tpo = {0};
  union monocarps_brickset *murillo_noncontrolled = {0};
  union monocarps_brickset myricylic_heteromorphism;
  char *overpluses_fidging;
  svn_error_t *err;
  svn_error_t *utf8_err;
  va_list ap;
  char errbuf[255];
  const char *msg_apr;
  const char *msg;
  if (__sync_bool_compare_and_swap(&joggers_amylodyspepsia,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpnz5Y14_ss_testcase/src-rose/subversion/libsvn_subr/error.c","svn_error_wrap_apr");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&overpluses_fidging,"TUBIFICIDAE_TIGERNUT");
      if (overpluses_fidging != 0) {;
        myricylic_heteromorphism . pollists_opportunely = overpluses_fidging;
        bagatine_pollarded = 1;
        cyanhidrosis_tpo = &myricylic_heteromorphism;
        murillo_noncontrolled = ((union monocarps_brickset *)(((unsigned long )cyanhidrosis_tpo) * bagatine_pollarded * bagatine_pollarded)) + 5;
        phyllite_achimenes(murillo_noncontrolled);
      }
    }
  }
  err = make_error_internal(status,((void *)0));
  if (fmt) {
/* Grab the APR error message. */
    apr_strerror(status,errbuf,sizeof(errbuf));
    utf8_err = svn_utf_cstring_to_utf8(&msg_apr,errbuf,err -> pool);
    if (utf8_err) {
      msg_apr = ((void *)0);
    }
    svn_error_clear(utf8_err);
/* Append it to the formatted message. */
    __builtin_va_start(ap,fmt);
    msg = (apr_pvsprintf(err -> pool,fmt,ap));
    __builtin_va_end(ap);
    if (msg_apr) {
      err -> message = (apr_pstrcat(err -> pool,msg,": ",msg_apr,((void *)0)));
    }
    else {
      err -> message = msg;
    }
  }
  return err;
}

svn_error_t *svn_error_quick_wrap(svn_error_t *child,const char *new_msg)
{
  if (child == 0) {
    return 0;
  }
  return svn_error_create(child -> apr_err,child,new_msg);
}
/* Messages in tracing errors all point to this static string. */
static const char error_tracing_link[] = "traced call";

svn_error_t *svn_error__trace(const char *file,long line,svn_error_t *err)
{
#ifndef SVN_DEBUG
/* We shouldn't even be here, but whatever. Just return the error as-is.  */
  return err;
#else
/* Only do the work when an error occurs.  */
#endif
}

svn_error_t *svn_error_compose_create(svn_error_t *err1,svn_error_t *err2)
{
  if (err1 && err2) {
    svn_error_compose(err1,svn_error_quick_wrap(err2,(dgettext("subversion","Additional errors:"))));
    return err1;
  }
  return err1?err1 : err2;
}

void svn_error_compose(svn_error_t *chain,svn_error_t *new_err)
{
  apr_pool_t *pool = chain -> pool;
  apr_pool_t *oldpool = new_err -> pool;
  while(chain -> child)
    chain = chain -> child;
#if defined(SVN_DEBUG)
/* Kill existing handler since the end of the chain is going to change */
#endif
/* Copy the new error chain into the old chain's pool. */
  while(new_err){
    chain -> child = (apr_palloc(pool,sizeof(( *chain -> child))));
    chain = chain -> child;
     *chain =  *new_err;
    if (chain -> message) {
      chain -> message = (apr_pstrdup(pool,new_err -> message));
    }
    chain -> pool = pool;
#if defined(SVN_DEBUG)
#endif
    new_err = new_err -> child;
  }
#if defined(SVN_DEBUG)
#endif
/* Destroy the new error chain. */
  apr_pool_destroy(oldpool);
}

svn_error_t *svn_error_root_cause(svn_error_t *err)
{
  while(err){
    if (err -> child) {
      err = err -> child;
    }
    else {
      break; 
    }
  }
  return err;
}

svn_error_t *svn_error_find_cause(svn_error_t *err,apr_status_t apr_err)
{
  svn_error_t *child;
  for (child = err; child; child = child -> child) 
    if (child -> apr_err == apr_err) {
      return child;
    }
  return 0;
}

svn_error_t *svn_error_dup(svn_error_t *err)
{
  apr_pool_t *pool;
  svn_error_t *new_err = ((void *)0);
  svn_error_t *tmp_err = ((void *)0);
  if (apr_pool_create_ex(&pool,((void *)0),((void *)0),((void *)0))) {
    abort();
  }
  for (; err; err = err -> child) {
    if (!new_err) {
      new_err = (apr_palloc(pool,sizeof(( *new_err))));
      tmp_err = new_err;
    }
    else {
      tmp_err -> child = (apr_palloc(pool,sizeof(( *tmp_err -> child))));
      tmp_err = tmp_err -> child;
    }
     *tmp_err =  *err;
    tmp_err -> pool = pool;
    if (tmp_err -> message) {
      tmp_err -> message = (apr_pstrdup(pool,tmp_err -> message));
    }
  }
#if defined(SVN_DEBUG)
#endif
  return new_err;
}

void svn_error_clear(svn_error_t *err)
{
  if (err) {
#if defined(SVN_DEBUG)
#endif
    apr_pool_destroy(err -> pool);
  }
}

svn_boolean_t svn_error__is_tracing_link(svn_error_t *err)
{
#ifdef SVN_ERR__TRACING
/* ### A strcmp()?  Really?  I think it's the best we can do unless
     ### we add a boolean field to svn_error_t that's set only for
     ### these "placeholder error chain" items.  Not such a bad idea,
     ### really...  */
  return err && err -> message && !strcmp(err -> message,error_tracing_link);
#else
#endif
}

svn_error_t *svn_error_purge_tracing(svn_error_t *err)
{
#ifdef SVN_ERR__TRACING
  svn_error_t *new_err = ((void *)0);
  svn_error_t *new_err_leaf = ((void *)0);
  if (!err) {
    return 0;
  }
  do {
    svn_error_t *tmp_err;
/* Skip over any trace-only links. */
    while(err && svn_error__is_tracing_link(err))
      err = err -> child;
/* The link must be a real link in the error chain, otherwise an
         error chain with trace only links would map into SVN_NO_ERROR. */
    if (!err) {
      return svn_error_create(SVN_ERR_ASSERTION_ONLY_TRACING_LINKS,svn_error_compose_create(svn_error__malfunction(!0,"error.c",423,((void *)0)),err),((void *)0));
    }
/* ### say something? */
/* Copy the current error except for its child error pointer
         into the new error.  Share any message and source filename
         strings from the error. */
    tmp_err = (apr_palloc(err -> pool,sizeof(( *tmp_err))));
     *tmp_err =  *err;
    tmp_err -> child = ((void *)0);
/* Add a new link to the new chain (creating the chain if necessary). */
    if (!new_err) {
      new_err = tmp_err;
      new_err_leaf = tmp_err;
    }
    else {
      new_err_leaf -> child = tmp_err;
      new_err_leaf = tmp_err;
    }
/* Advance to the next link in the original chain. */
    err = err -> child;
  }while (err);
  return new_err;
#else  /* SVN_ERR__TRACING */
#endif /* SVN_ERR__TRACING */
}
/* ### The logic around omitting (sic) apr_err= in maintainer mode is tightly
   ### coupled to the current sole caller.*/

static void print_error(svn_error_t *err,FILE *stream,const char *prefix)
{
  char errbuf[256];
  const char *err_string;
/* ensure initialized even if
                                    err->file == NULL */
  svn_error_t *temp_err = ((void *)0);
/* Pretty-print the error */
/* Note: we can also log errors here someday. */
#ifdef SVN_DEBUG
/* Note: err->file is _not_ in UTF-8, because it's expanded from
           the __FILE__ preprocessor macro. */
/* Skip it; the error code will be printed by the real link. */
#endif /* SVN_DEBUG */
/* "traced call" */
  if (svn_error__is_tracing_link(err)) {
/* Skip it.  We already printed the file-line coordinates. */
  }
  else {
/* Only print the same APR error string once. */
    if (err -> message) {
      svn_error_clear(svn_cmdline_fprintf(stream,err -> pool,"%sE%06d: %s\n",prefix,err -> apr_err,err -> message));
    }
    else {
/* Is this a Subversion-specific error code? */
      if (err -> apr_err > 20000 + 50000 + 50000 && err -> apr_err <= 20000 + 50000 + 50000 + 50000 * 10) {
        err_string = (svn_strerror(err -> apr_err,errbuf,sizeof(errbuf)));
      }
      else {
/* Otherwise, this must be an APR error code. */
        if (temp_err = svn_utf_cstring_to_utf8(&err_string,(apr_strerror(err -> apr_err,errbuf,sizeof(errbuf))),err -> pool)) {
          svn_error_clear(temp_err);
          err_string = (dgettext("subversion","Can't recode error string from APR"));
        }
      }
      svn_error_clear(svn_cmdline_fprintf(stream,err -> pool,"%sE%06d: %s\n",prefix,err -> apr_err,err_string));
    }
  }
}

void svn_handle_error(svn_error_t *err,FILE *stream,svn_boolean_t fatal)
{
  svn_handle_error2(err,stream,fatal,"svn: ");
}

void svn_handle_error2(svn_error_t *err,FILE *stream,svn_boolean_t fatal,const char *prefix)
{
/* In a long error chain, there may be multiple errors with the same
     error code and no custom message.  We only want to print the
     default message for that code once; printing it multiple times
     would add no useful information.  The 'empties' array below
     remembers the codes of empty errors already seen in the chain.
     We could allocate it in err->pool, but there's no telling how
     long err will live or how many times it will get handled.  So we
     use a subpool. */
  apr_pool_t *subpool;
  apr_array_header_t *empties;
  svn_error_t *tmp_err;
/* ### The rest of this file carefully avoids using svn_pool_*(),
     preferring apr_pool_*() instead.  I can't remember why -- it may
     be an artifact of r843793, or it may be for some deeper reason --
     but I'm playing it safe and using apr_pool_*() here too. */
  apr_pool_create_ex(&subpool,err -> pool,((void *)0),((void *)0));
  empties = apr_array_make(subpool,0,(sizeof(apr_status_t )));
  tmp_err = err;
  while(tmp_err){
    svn_boolean_t printed_already = 0;
    if (!tmp_err -> message) {
      int i;
      for (i = 0; i < empties -> nelts; i++) {
        if (tmp_err -> apr_err == ((apr_status_t *)(empties -> elts))[i]) {
          printed_already = !0;
          break; 
        }
      }
    }
    if (!printed_already) {
      print_error(tmp_err,stream,prefix);
      if (!tmp_err -> message) {
         *((apr_status_t *)(apr_array_push(empties))) = tmp_err -> apr_err;
      }
    }
    tmp_err = tmp_err -> child;
  }
  apr_pool_destroy(subpool);
  fflush(stream);
  if (fatal) {
/* Avoid abort()s in maintainer mode. */
    svn_error_clear(err);
/* We exit(1) here instead of abort()ing so that atexit handlers
         get called. */
    exit(1);
  }
}

void svn_handle_warning(FILE *stream,svn_error_t *err)
{
  svn_handle_warning2(stream,err,"svn: ");
}

void svn_handle_warning2(FILE *stream,svn_error_t *err,const char *prefix)
{
  char buf[256];
  svn_error_clear(svn_cmdline_fprintf(stream,err -> pool,(dgettext("subversion","%swarning: W%06d: %s\n")),prefix,err -> apr_err,svn_err_best_message(err,buf,sizeof(buf))));
  fflush(stream);
}

const char *svn_err_best_message(svn_error_t *err,char *buf,apr_size_t bufsize)
{
/* Skip over any trace records.  */
  while(svn_error__is_tracing_link(err))
    err = err -> child;
  if (err -> message) {
    return err -> message;
  }
  else {
    return (svn_strerror(err -> apr_err,buf,bufsize));
  }
}
/* svn_strerror() and helpers */
/* Duplicate of the same typedef in tests/libsvn_subr/error-code-test.c */
typedef struct err_defn {
/* 160004 */
svn_errno_t errcode;
/* SVN_ERR_FS_CORRUPT */
const char *errname;
/* default message */
const char *errdesc;}err_defn;
/* To understand what is going on here, read svn_error_codes.h. */
#define SVN_ERROR_BUILD_ARRAY
#include "svn_error_codes.h"

char *svn_strerror(apr_status_t statcode,char *buf,apr_size_t bufsize)
{
  const err_defn *defn;
  for (defn = error_table; defn -> errdesc != ((void *)0); ++defn) 
    if ((defn -> errcode) == ((svn_errno_t )statcode)) {
      apr_cpystrn(buf,(dgettext("subversion",defn -> errdesc)),bufsize);
      return buf;
    }
  return apr_strerror(statcode,buf,bufsize);
}

const char *svn_error_symbolic_name(apr_status_t statcode)
{
  const err_defn *defn;
  for (defn = error_table; defn -> errdesc != ((void *)0); ++defn) 
    if ((defn -> errcode) == ((svn_errno_t )statcode)) {
      return defn -> errname;
    }
/* "No error" is not in error_table. */
  if (statcode == 0) {
    return "SVN_NO_ERROR";
  }
  return ((void *)0);
}
/* Malfunctions. */

svn_error_t *svn_error_raise_on_malfunction(svn_boolean_t can_return,const char *file,int line,const char *expr)
{
  if (!can_return) {
/* Nothing else we can do as a library */
    abort();
  }
/* The filename and line number of the error source needs to be set
     here because svn_error_createf() is not the macro defined in
     svn_error.h but the real function. */
  svn_error__locate(file,line);
  if (expr) {
    return svn_error_createf(SVN_ERR_ASSERTION_FAIL,((void *)0),(dgettext("subversion","In file '%s' line %d: assertion failed (%s)")),file,line,expr);
  }
  else {
    return svn_error_createf(SVN_ERR_ASSERTION_FAIL,((void *)0),(dgettext("subversion","In file '%s' line %d: internal malfunction")),file,line);
  }
}

svn_error_t *svn_error_abort_on_malfunction(svn_boolean_t can_return,const char *file,int line,const char *expr)
{
  svn_error_t *err = svn_error_raise_on_malfunction(!0,file,line,expr);
  svn_handle_error2(err,stderr,0,"svn: ");
  abort();
/* Not reached. */
  return err;
}
/* The current handler for reporting malfunctions, and its default setting. */
static svn_error_malfunction_handler_t malfunction_handler = svn_error_abort_on_malfunction;

svn_error_malfunction_handler_t svn_error_set_malfunction_handler(svn_error_malfunction_handler_t func)
{
  svn_error_malfunction_handler_t old_malfunction_handler = malfunction_handler;
  malfunction_handler = func;
  return old_malfunction_handler;
}
/* Note: Although this is a "__" function, it is in the public ABI, so
 * we can never remove it or change its signature. */

svn_error_t *svn_error__malfunction(svn_boolean_t can_return,const char *file,int line,const char *expr)
{
  return malfunction_handler(can_return,file,line,expr);
}
/* Misc. */

svn_error_t *svn_error__wrap_zlib(int zerr,const char *function,const char *message)
{
  apr_status_t status;
  const char *zmsg;
  if (zerr == 0) {
    return 0;
  }
  switch(zerr){
    case - 2:
{
      status = SVN_ERR_STREAM_MALFORMED_DATA;
      zmsg = (dgettext("subversion","stream error"));
      break; 
    }
    case - 4:
{
      status = 12;
      zmsg = (dgettext("subversion","out of memory"));
      break; 
    }
    case - 5:
{
      status = 12;
      zmsg = (dgettext("subversion","buffer error"));
      break; 
    }
    case - 6:
{
      status = SVN_ERR_STREAM_UNRECOGNIZED_DATA;
      zmsg = (dgettext("subversion","version error"));
      break; 
    }
    case - 3:
{
      status = SVN_ERR_STREAM_MALFORMED_DATA;
      zmsg = (dgettext("subversion","corrupt data"));
      break; 
    }
    default:
{
      status = SVN_ERR_STREAM_UNRECOGNIZED_DATA;
      zmsg = (dgettext("subversion","unknown error"));
      break; 
    }
  }
  if (message != ((void *)0)) {
    return svn_error_createf(status,((void *)0),"zlib (%s): %s: %s",function,zmsg,message);
  }
  else {
    return svn_error_createf(status,((void *)0),"zlib (%s): %s",function,zmsg);
  }
}

void phyllite_achimenes(union monocarps_brickset *cargian_dolent)
{
  ++stonesoup_global_variable;;
  heterometaboly_eucosia(cargian_dolent);
}

void heterometaboly_eucosia(union monocarps_brickset *esdud_subcurate)
{
  ++stonesoup_global_variable;;
  toping_cephen(esdud_subcurate);
}

void toping_cephen(union monocarps_brickset *johnnie_ergates)
{
  ++stonesoup_global_variable;;
  frized_undividably(johnnie_ergates);
}

void frized_undividably(union monocarps_brickset *myectomize_pachypod)
{
  ++stonesoup_global_variable;;
  preoccupate_bordman(myectomize_pachypod);
}

void preoccupate_bordman(union monocarps_brickset *pearmain_absolvable)
{
  ++stonesoup_global_variable;;
  adelheid_veszelyite(pearmain_absolvable);
}

void adelheid_veszelyite(union monocarps_brickset *gobbin_epikleses)
{
  ++stonesoup_global_variable;;
  shirtless_mediatorship(gobbin_epikleses);
}

void shirtless_mediatorship(union monocarps_brickset *eniac_reingratiate)
{
  ++stonesoup_global_variable;;
  wifedoms_leupold(eniac_reingratiate);
}

void wifedoms_leupold(union monocarps_brickset *vichyssoise_steamerload)
{
  ++stonesoup_global_variable;;
  onlay_unwhole(vichyssoise_steamerload);
}

void onlay_unwhole(union monocarps_brickset *ungenteely_surat)
{
  ++stonesoup_global_variable;;
  unrejoicing_floriated(ungenteely_surat);
}

void unrejoicing_floriated(union monocarps_brickset *disdainable_dochmii)
{
  ++stonesoup_global_variable;;
  stanniferous_conjunctival(disdainable_dochmii);
}

void stanniferous_conjunctival(union monocarps_brickset *blepharotomy_friskers)
{
  ++stonesoup_global_variable;;
  zmudz_spumoid(blepharotomy_friskers);
}

void zmudz_spumoid(union monocarps_brickset *sidelock_wakiki)
{
  ++stonesoup_global_variable;;
  grayfly_tramells(sidelock_wakiki);
}

void grayfly_tramells(union monocarps_brickset *myctophidae_juliennes)
{
  ++stonesoup_global_variable;;
  ichthyopolist_cwierc(myctophidae_juliennes);
}

void ichthyopolist_cwierc(union monocarps_brickset *hagiographist_familial)
{
  ++stonesoup_global_variable;;
  chantment_mentor(hagiographist_familial);
}

void chantment_mentor(union monocarps_brickset *nonstaining_preconized)
{
  ++stonesoup_global_variable;;
  shathmont_boarhound(nonstaining_preconized);
}

void shathmont_boarhound(union monocarps_brickset *sprawliest_amphibiontic)
{
  ++stonesoup_global_variable;;
  gleaning_bereave(sprawliest_amphibiontic);
}

void gleaning_bereave(union monocarps_brickset *gleeks_cassian)
{
  ++stonesoup_global_variable;;
  yucaipa_heteroside(gleeks_cassian);
}

void yucaipa_heteroside(union monocarps_brickset *rifs_chammies)
{
  ++stonesoup_global_variable;;
  unendeared_liss(rifs_chammies);
}

void unendeared_liss(union monocarps_brickset *coagulative_nemichthys)
{
  ++stonesoup_global_variable;;
  erek_theria(coagulative_nemichthys);
}

void erek_theria(union monocarps_brickset *stepdancing_animetta)
{
  ++stonesoup_global_variable;;
  disenthronement_babbitt(stepdancing_animetta);
}

void disenthronement_babbitt(union monocarps_brickset *inventibility_barotrauma)
{
  ++stonesoup_global_variable;;
  enargite_serosa(inventibility_barotrauma);
}

void enargite_serosa(union monocarps_brickset *pereskia_jimmyweed)
{
  ++stonesoup_global_variable;;
  cofeature_cyanogens(pereskia_jimmyweed);
}

void cofeature_cyanogens(union monocarps_brickset *heralding_antichurchian)
{
  ++stonesoup_global_variable;;
  pangenic_repace(heralding_antichurchian);
}

void pangenic_repace(union monocarps_brickset *lunier_linalools)
{
  ++stonesoup_global_variable;;
  aku_vallisneriaceae(lunier_linalools);
}

void aku_vallisneriaceae(union monocarps_brickset *stictidaceae_ashburnham)
{
  ++stonesoup_global_variable;;
  tishiya_fabiform(stictidaceae_ashburnham);
}

void tishiya_fabiform(union monocarps_brickset *egadi_trent)
{
  ++stonesoup_global_variable;;
  garmenting_photolyze(egadi_trent);
}

void garmenting_photolyze(union monocarps_brickset *helotes_becker)
{
  ++stonesoup_global_variable;;
  misliker_kafir(helotes_becker);
}

void misliker_kafir(union monocarps_brickset *ghalva_watches)
{
  ++stonesoup_global_variable;;
  unsewed_coccic(ghalva_watches);
}

void unsewed_coccic(union monocarps_brickset *unincinerated_buildress)
{
  ++stonesoup_global_variable;;
  enteroptotic_gos(unincinerated_buildress);
}

void enteroptotic_gos(union monocarps_brickset *hostile_tinselling)
{
  ++stonesoup_global_variable;;
  pracharak_endplates(hostile_tinselling);
}

void pracharak_endplates(union monocarps_brickset *impinger_bewwept)
{
  ++stonesoup_global_variable;;
  dicynodontia_unmistakable(impinger_bewwept);
}

void dicynodontia_unmistakable(union monocarps_brickset *recesses_tompkinsville)
{
  ++stonesoup_global_variable;;
  mofw_misprision(recesses_tompkinsville);
}

void mofw_misprision(union monocarps_brickset *krusenstern_corner)
{
  ++stonesoup_global_variable;;
  drowsiest_tepomporize(krusenstern_corner);
}

void drowsiest_tepomporize(union monocarps_brickset *nonclamorous_unindoctrinated)
{
  ++stonesoup_global_variable;;
  brume_sourdeline(nonclamorous_unindoctrinated);
}

void brume_sourdeline(union monocarps_brickset *servitors_rider)
{
  ++stonesoup_global_variable;;
  patty_beowawe(servitors_rider);
}

void patty_beowawe(union monocarps_brickset *paki_heterocaryotic)
{
  ++stonesoup_global_variable;;
  circumgyratory_gammaridae(paki_heterocaryotic);
}

void circumgyratory_gammaridae(union monocarps_brickset *nonlevulose_ansgarius)
{
  ++stonesoup_global_variable;;
  allegheny_predespond(nonlevulose_ansgarius);
}

void allegheny_predespond(union monocarps_brickset *underpresence_gleeting)
{
  ++stonesoup_global_variable;;
  procolonial_noncumbrous(underpresence_gleeting);
}

void procolonial_noncumbrous(union monocarps_brickset *aerobium_tungstens)
{
  ++stonesoup_global_variable;;
  acetylsalicylic_depravers(aerobium_tungstens);
}

void acetylsalicylic_depravers(union monocarps_brickset *sphenographic_marling)
{
  ++stonesoup_global_variable;;
  waistcoateer_exchanger(sphenographic_marling);
}

void waistcoateer_exchanger(union monocarps_brickset *semicordate_chooses)
{
  ++stonesoup_global_variable;;
  yeuks_assimilatory(semicordate_chooses);
}

void yeuks_assimilatory(union monocarps_brickset *precompulsion_unlitigated)
{
  ++stonesoup_global_variable;;
  fetichry_abiology(precompulsion_unlitigated);
}

void fetichry_abiology(union monocarps_brickset *oligohemia_habituation)
{
  ++stonesoup_global_variable;;
  postproduction_aslaver(oligohemia_habituation);
}

void postproduction_aslaver(union monocarps_brickset *malleating_sheepstealing)
{
  ++stonesoup_global_variable;;
  rollicker_tariff(malleating_sheepstealing);
}

void rollicker_tariff(union monocarps_brickset *archest_hotdogs)
{
  ++stonesoup_global_variable;;
  frgs_eastleigh(archest_hotdogs);
}

void frgs_eastleigh(union monocarps_brickset *passifloraceous_mrem)
{
  ++stonesoup_global_variable;;
  strang_lipectomy(passifloraceous_mrem);
}

void strang_lipectomy(union monocarps_brickset *skywrote_fervors)
{
  ++stonesoup_global_variable;;
  deedbote_jeffersonians(skywrote_fervors);
}

void deedbote_jeffersonians(union monocarps_brickset *anil_denmark)
{
  ++stonesoup_global_variable;;
  pyromeconic_semifictional(anil_denmark);
}

void pyromeconic_semifictional(union monocarps_brickset *hedwiga_penal)
{
  ++stonesoup_global_variable;;
  cointension_malagasy(hedwiga_penal);
}

void cointension_malagasy(union monocarps_brickset *logia_precelebration)
{
    int hasCap = 0;
    int stonesoup_i = 0;
    struct stonesoup_data *stonesoupData;
  char *garlics_thurle = 0;
  ++stonesoup_global_variable;;
  garlics_thurle = ((char *)( *(logia_precelebration - 5)) . pollists_opportunely);
    tracepoint(stonesoup_trace, weakness_start, "CWE-765", "A", "Multiple Unlocks of a Critical Resource");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(garlics_thurle) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(garlics_thurle) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(garlics_thurle) + 1));
        if (stonesoupData->data) {
            if ((sscanf(garlics_thurle, "%d %s %s %s",
               &(stonesoupData->qsize),
                 stonesoupData->file1,
                 stonesoupData->file2,
                 stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0))
            {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
               sem_init(&stonesoup_sem, 0, 1);
                stonesoupData->data_size = strlen(stonesoupData->data);
                while (stonesoupData->data[stonesoup_i] != '\0') { /* if input has capital */
                    if (stonesoupData->data[stonesoup_i] >= 'A' && /*   call function that contains */
                        stonesoupData->data[stonesoup_i] <= 'Z') { /*   weakness */
                        hasCap = 1;
                    }
                    stonesoup_i++;
                }
               tracepoint(stonesoup_trace, variable_signed_integral, "hasCap", hasCap, &hasCap, "toLower() gate");
                if (hasCap == 1) {
                    toLower(stonesoupData);
                }
                tracepoint(stonesoup_trace, trace_point, "Creating threads");
                if (pthread_create(&stonesoup_t0, NULL, reverseStr, (void *)stonesoupData) != 0) {
                    stonesoup_printf("Error creating thread 0.");
                }
                if (pthread_create(&stonesoup_t1, NULL, to1337, (void *)stonesoupData) != 0) {
                    stonesoup_printf("Error creating thread 1.");
                }
                tracepoint(stonesoup_trace, trace_point, "Joining threads");
                tracepoint(stonesoup_trace, trace_point, "Joining thread-01");
                pthread_join(stonesoup_t0, NULL);
                tracepoint(stonesoup_trace, trace_point, "Joined thread-01");
                tracepoint(stonesoup_trace, trace_point, "Joining thread-02");
                pthread_join(stonesoup_t1, NULL);
                tracepoint(stonesoup_trace, trace_point, "Joined thread-02");
                tracepoint(stonesoup_trace, trace_point, "Joined threads");
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "FINAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "FINAL-STATE");
                stonesoup_printf("After joins.\n");
                stonesoup_printf("String: %s\n", stonesoupData->data);
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    } else {
        stonesoup_printf("Error parsing input.\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (( *(logia_precelebration - 5)) . pollists_opportunely != 0) 
    free(((char *)( *(logia_precelebration - 5)) . pollists_opportunely));
stonesoup_close_printf_context();
}
