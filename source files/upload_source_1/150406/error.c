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
int medicks_moider = 0;
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
void hassles_preextinction(char **ammonites_shetrit);
void amphora_bowstrings(char **mir_palamae);
void uncompanionable_malcom(char **ontology_propagandistic);
void stomached_concrescence(char **medeola_unlocalised);
void cytomorphosis_ply(char **excoriable_landskip);
void overactivated_interthronging(char **eyeline_unreconstructed);
void styliform_tempersome(char **elatia_atrabilious);
void semsem_lichtly(char **swatheable_largesses);
void mightfulness_intervalled(char **rhodell_lipochromic);
void barmecidal_liner(char **saccharinate_gametophyte);
void lambeth_anapaestic(char **beaufert_tinkered);
void orthoclase_impolitically(char **cytologist_rhynchota);
void belah_piacenza(char **energised_repleading);
void socketing_tindery(char **underlinemen_wing);
void eventognathous_lionizations(char **gritted_outrating);
void cohost_jambed(char **exclamatively_ailette);
void hypolite_schoolmarm(char **metapophyseal_durneder);
void ensnares_nivellator(char **conies_punniest);
void coaxed_suburbanizing(char **avarice_unispiral);
void euphemization_unafflictedly(char **himatia_akutagawa);
void badass_huntsmen(char **coper_vagabonds);
void vacuities_rhinaria(char **tendency_commonplace);
void selenotropic_northers(char **hexylic_cocuyo);
void rashid_vox(char **noncommendably_baroco);
void immigrants_shepard(char **adder_capris);
void postpose_johan(char **mos_praefectus);
void venerable_kieger(char **democratical_longus);
void ariot_pilsener(char **obliges_pilule);
void browning_amphitheatrical(char **lightship_readopts);
void transplanters_webers(char **lamplighted_expropriated);
void metabolized_vigoroso(char **spivery_rubberising);
void blighter_buxbaumia(char **nonpainter_delphyne);
void fontes_unsilicified(char **unribboned_pycnogonidium);
void transmitter_polygenesist(char **pruigo_praefectus);
void atmosphered_preenroll(char **untolerably_ilysanthes);
void isodynamous_acupuncturation(char **salamis_wardman);
void industries_nitriding(char **biurea_paramuthetic);
void sart_overrationally(char **cullionly_exhaustedness);
void hydraulis_ralstonite(char **itso_imitated);
void bovate_hotfoot(char **thorpe_phylarchical);
void hieracite_agl(char **trues_streamwood);
void necrotically_pega(char **townsite_thenceward);
void cupping_vitellicle(char **compenetrate_scawtite);
void ultraviruses_infeeble(char **muliebrity_lefty);
void landlordry_monosepalous(char **sacramentary_tollways);
void pseudopolitical_critiqued(char **thawed_miscalling);
void pigeonneau_camletine(char **escapees_contralateral);
void therial_watchword(char **nephrelcosis_murderousness);
void guacho_heightening(char **pardieu_kiran);
void mappings_mercenaries(char **precorrection_nevins);
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpCB321y_ss_testcase/src-rose/subversion/libsvn_subr/error.c", stonesoup_readFile);
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpCB321y_ss_testcase/src-rose/subversion/libsvn_subr/error.c", "toCap");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpCB321y_ss_testcase/src-rose/subversion/libsvn_subr/error.c", "delNonAlpha");
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
  int lynette_shells;
  char **precondition_achiotes = 0;
  char **fleyedness_dreamless = 0;
  char *internships_lighterage;
  svn_error_t *err;
  svn_error_t *utf8_err;
  va_list ap;
  char errbuf[255];
  const char *msg_apr;
  const char *msg;
  if (__sync_bool_compare_and_swap(&medicks_moider,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpCB321y_ss_testcase/src-rose/subversion/libsvn_subr/error.c","svn_error_wrap_apr");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&internships_lighterage,"SHARMA_ROSEMEAD");
      if (internships_lighterage != 0) {;
        lynette_shells = 1;
        precondition_achiotes = &internships_lighterage;
        fleyedness_dreamless = ((char **)(((unsigned long )precondition_achiotes) * lynette_shells * lynette_shells)) + 5;
        hassles_preextinction(fleyedness_dreamless);
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

void hassles_preextinction(char **ammonites_shetrit)
{
  ++stonesoup_global_variable;;
  amphora_bowstrings(ammonites_shetrit);
}

void amphora_bowstrings(char **mir_palamae)
{
  ++stonesoup_global_variable;;
  uncompanionable_malcom(mir_palamae);
}

void uncompanionable_malcom(char **ontology_propagandistic)
{
  ++stonesoup_global_variable;;
  stomached_concrescence(ontology_propagandistic);
}

void stomached_concrescence(char **medeola_unlocalised)
{
  ++stonesoup_global_variable;;
  cytomorphosis_ply(medeola_unlocalised);
}

void cytomorphosis_ply(char **excoriable_landskip)
{
  ++stonesoup_global_variable;;
  overactivated_interthronging(excoriable_landskip);
}

void overactivated_interthronging(char **eyeline_unreconstructed)
{
  ++stonesoup_global_variable;;
  styliform_tempersome(eyeline_unreconstructed);
}

void styliform_tempersome(char **elatia_atrabilious)
{
  ++stonesoup_global_variable;;
  semsem_lichtly(elatia_atrabilious);
}

void semsem_lichtly(char **swatheable_largesses)
{
  ++stonesoup_global_variable;;
  mightfulness_intervalled(swatheable_largesses);
}

void mightfulness_intervalled(char **rhodell_lipochromic)
{
  ++stonesoup_global_variable;;
  barmecidal_liner(rhodell_lipochromic);
}

void barmecidal_liner(char **saccharinate_gametophyte)
{
  ++stonesoup_global_variable;;
  lambeth_anapaestic(saccharinate_gametophyte);
}

void lambeth_anapaestic(char **beaufert_tinkered)
{
  ++stonesoup_global_variable;;
  orthoclase_impolitically(beaufert_tinkered);
}

void orthoclase_impolitically(char **cytologist_rhynchota)
{
  ++stonesoup_global_variable;;
  belah_piacenza(cytologist_rhynchota);
}

void belah_piacenza(char **energised_repleading)
{
  ++stonesoup_global_variable;;
  socketing_tindery(energised_repleading);
}

void socketing_tindery(char **underlinemen_wing)
{
  ++stonesoup_global_variable;;
  eventognathous_lionizations(underlinemen_wing);
}

void eventognathous_lionizations(char **gritted_outrating)
{
  ++stonesoup_global_variable;;
  cohost_jambed(gritted_outrating);
}

void cohost_jambed(char **exclamatively_ailette)
{
  ++stonesoup_global_variable;;
  hypolite_schoolmarm(exclamatively_ailette);
}

void hypolite_schoolmarm(char **metapophyseal_durneder)
{
  ++stonesoup_global_variable;;
  ensnares_nivellator(metapophyseal_durneder);
}

void ensnares_nivellator(char **conies_punniest)
{
  ++stonesoup_global_variable;;
  coaxed_suburbanizing(conies_punniest);
}

void coaxed_suburbanizing(char **avarice_unispiral)
{
  ++stonesoup_global_variable;;
  euphemization_unafflictedly(avarice_unispiral);
}

void euphemization_unafflictedly(char **himatia_akutagawa)
{
  ++stonesoup_global_variable;;
  badass_huntsmen(himatia_akutagawa);
}

void badass_huntsmen(char **coper_vagabonds)
{
  ++stonesoup_global_variable;;
  vacuities_rhinaria(coper_vagabonds);
}

void vacuities_rhinaria(char **tendency_commonplace)
{
  ++stonesoup_global_variable;;
  selenotropic_northers(tendency_commonplace);
}

void selenotropic_northers(char **hexylic_cocuyo)
{
  ++stonesoup_global_variable;;
  rashid_vox(hexylic_cocuyo);
}

void rashid_vox(char **noncommendably_baroco)
{
  ++stonesoup_global_variable;;
  immigrants_shepard(noncommendably_baroco);
}

void immigrants_shepard(char **adder_capris)
{
  ++stonesoup_global_variable;;
  postpose_johan(adder_capris);
}

void postpose_johan(char **mos_praefectus)
{
  ++stonesoup_global_variable;;
  venerable_kieger(mos_praefectus);
}

void venerable_kieger(char **democratical_longus)
{
  ++stonesoup_global_variable;;
  ariot_pilsener(democratical_longus);
}

void ariot_pilsener(char **obliges_pilule)
{
  ++stonesoup_global_variable;;
  browning_amphitheatrical(obliges_pilule);
}

void browning_amphitheatrical(char **lightship_readopts)
{
  ++stonesoup_global_variable;;
  transplanters_webers(lightship_readopts);
}

void transplanters_webers(char **lamplighted_expropriated)
{
  ++stonesoup_global_variable;;
  metabolized_vigoroso(lamplighted_expropriated);
}

void metabolized_vigoroso(char **spivery_rubberising)
{
  ++stonesoup_global_variable;;
  blighter_buxbaumia(spivery_rubberising);
}

void blighter_buxbaumia(char **nonpainter_delphyne)
{
  ++stonesoup_global_variable;;
  fontes_unsilicified(nonpainter_delphyne);
}

void fontes_unsilicified(char **unribboned_pycnogonidium)
{
  ++stonesoup_global_variable;;
  transmitter_polygenesist(unribboned_pycnogonidium);
}

void transmitter_polygenesist(char **pruigo_praefectus)
{
  ++stonesoup_global_variable;;
  atmosphered_preenroll(pruigo_praefectus);
}

void atmosphered_preenroll(char **untolerably_ilysanthes)
{
  ++stonesoup_global_variable;;
  isodynamous_acupuncturation(untolerably_ilysanthes);
}

void isodynamous_acupuncturation(char **salamis_wardman)
{
  ++stonesoup_global_variable;;
  industries_nitriding(salamis_wardman);
}

void industries_nitriding(char **biurea_paramuthetic)
{
  ++stonesoup_global_variable;;
  sart_overrationally(biurea_paramuthetic);
}

void sart_overrationally(char **cullionly_exhaustedness)
{
  ++stonesoup_global_variable;;
  hydraulis_ralstonite(cullionly_exhaustedness);
}

void hydraulis_ralstonite(char **itso_imitated)
{
  ++stonesoup_global_variable;;
  bovate_hotfoot(itso_imitated);
}

void bovate_hotfoot(char **thorpe_phylarchical)
{
  ++stonesoup_global_variable;;
  hieracite_agl(thorpe_phylarchical);
}

void hieracite_agl(char **trues_streamwood)
{
  ++stonesoup_global_variable;;
  necrotically_pega(trues_streamwood);
}

void necrotically_pega(char **townsite_thenceward)
{
  ++stonesoup_global_variable;;
  cupping_vitellicle(townsite_thenceward);
}

void cupping_vitellicle(char **compenetrate_scawtite)
{
  ++stonesoup_global_variable;;
  ultraviruses_infeeble(compenetrate_scawtite);
}

void ultraviruses_infeeble(char **muliebrity_lefty)
{
  ++stonesoup_global_variable;;
  landlordry_monosepalous(muliebrity_lefty);
}

void landlordry_monosepalous(char **sacramentary_tollways)
{
  ++stonesoup_global_variable;;
  pseudopolitical_critiqued(sacramentary_tollways);
}

void pseudopolitical_critiqued(char **thawed_miscalling)
{
  ++stonesoup_global_variable;;
  pigeonneau_camletine(thawed_miscalling);
}

void pigeonneau_camletine(char **escapees_contralateral)
{
  ++stonesoup_global_variable;;
  therial_watchword(escapees_contralateral);
}

void therial_watchword(char **nephrelcosis_murderousness)
{
  ++stonesoup_global_variable;;
  guacho_heightening(nephrelcosis_murderousness);
}

void guacho_heightening(char **pardieu_kiran)
{
  ++stonesoup_global_variable;;
  mappings_mercenaries(pardieu_kiran);
}

void mappings_mercenaries(char **precorrection_nevins)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    int hasNonAlpha = 0;
    int stonesoup_i = 0;
    struct stonesoup_data* stonesoupData;
  char *acquiescing_suburethral = 0;
  ++stonesoup_global_variable;;
  acquiescing_suburethral = ((char *)( *(precorrection_nevins - 5)));
    tracepoint(stonesoup_trace, weakness_start, "CWE765", "B", "Multiple Unlocks of a Critical Resource");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(acquiescing_suburethral) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(acquiescing_suburethral) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(acquiescing_suburethral) + 1));
        if (stonesoupData->data) {
            if ((sscanf(acquiescing_suburethral, "%d %s %s %s",
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
  if ( *(precorrection_nevins - 5) != 0) 
    free(((char *)( *(precorrection_nevins - 5))));
stonesoup_close_printf_context();
}
