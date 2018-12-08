/*
 * svn_types.c :  Implementation for Subversion's data types.
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
#include <apr_pools.h>
#include <apr_uuid.h>
#include "svn_hash.h"
#include "svn_types.h"
#include "svn_error.h"
#include "svn_string.h"
#include "svn_props.h"
#include "svn_private_config.h"
#include <sys/stat.h> 
#include <stdio.h> 
#include <libpq-fe.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <dlfcn.h> 
#include <time.h> 
int superperfectly_luminesce = 0;
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
void locater_acrothoracica(int unbrakes_firecrackers,char ***************************************************cauterise_dichogamic);

svn_error_t *svn_revnum_parse(svn_revnum_t *rev,const char *str,const char **endptr)
{
  char *end;
  svn_revnum_t result = strtol(str,&end,10);
  if (endptr) {
     *endptr = end;
  }
  if (str == end) {
    return svn_error_createf(SVN_ERR_REVNUM_PARSE_FAILURE,((void *)0),(dgettext("subversion","Invalid revision number found parsing '%s'")),str);
  }
  if (result < 0) {
/* The end pointer from strtol() is valid, but a negative revision
         number is invalid, so move the end pointer back to the
         beginning of the string. */
    if (endptr) {
       *endptr = str;
    }
    return svn_error_createf(SVN_ERR_REVNUM_PARSE_FAILURE,((void *)0),(dgettext("subversion","Negative revision number found parsing '%s'")),str);
  }
   *rev = result;
  return 0;
}

const char *svn_uuid_generate(apr_pool_t *pool)
{
  apr_uuid_t uuid;
  char *uuid_str = (memset(apr_palloc(pool,(36 + 1)),0,(36 + 1)));
  apr_uuid_get(&uuid);
  apr_uuid_format(uuid_str,(&uuid));
  return uuid_str;
}

const char *svn_depth_to_word(svn_depth_t depth)
{
  switch(depth){
    case svn_depth_exclude:
    return "exclude";
    case svn_depth_unknown:
    return "unknown";
    case svn_depth_empty:
    return "empty";
    case svn_depth_files:
    return "files";
    case svn_depth_immediates:
    return "immediates";
    case svn_depth_infinity:
    return "infinity";
    default:
    return "INVALID-DEPTH";
  }
}

svn_depth_t svn_depth_from_word(const char *word)
{
  if (strcmp(word,"exclude") == 0) {
    return svn_depth_exclude;
  }
  if (strcmp(word,"unknown") == 0) {
    return svn_depth_unknown;
  }
  if (strcmp(word,"empty") == 0) {
    return svn_depth_empty;
  }
  if (strcmp(word,"files") == 0) {
    return svn_depth_files;
  }
  if (strcmp(word,"immediates") == 0) {
    return svn_depth_immediates;
  }
  if (strcmp(word,"infinity") == 0) {
    return svn_depth_infinity;
  }
/* There's no special value for invalid depth, and no convincing
     reason to make one yet, so just fall back to unknown depth.
     If you ever change that convention, check callers to make sure
     they're not depending on it (e.g., option parsing in main() ).
  */
  return svn_depth_unknown;
}

const char *svn_node_kind_to_word(svn_node_kind_t kind)
{
  switch(kind){
    case svn_node_none:
    return "none";
    case svn_node_file:
    return "file";
    case svn_node_dir:
    return "dir";
    case svn_node_symlink:
    return "symlink";
    case svn_node_unknown:
{
    }
    default:
    return "unknown";
  }
}

svn_node_kind_t svn_node_kind_from_word(const char *word)
{
  if (word == ((void *)0)) {
    return svn_node_unknown;
  }
  if (strcmp(word,"none") == 0) {
    return svn_node_none;
  }
  else {
    if (strcmp(word,"file") == 0) {
      return svn_node_file;
    }
    else {
      if (strcmp(word,"dir") == 0) {
        return svn_node_dir;
      }
      else {
        if (strcmp(word,"symlink") == 0) {
          return svn_node_symlink;
        }
        else {
/* This also handles word == "unknown" */
          return svn_node_unknown;
        }
      }
    }
  }
}

const char *svn_tristate__to_word(svn_tristate_t tristate)
{
  switch(tristate){
    case svn_tristate_false:
    return "false";
    case svn_tristate_true:
    return "true";
    case svn_tristate_unknown:
{
    }
    default:
    return ((void *)0);
  }
}

svn_tristate_t svn_tristate__from_word(const char *word)
{
  int astrogate_gifture = 7;
  char ***************************************************vikky_faure = 0;
  char **************************************************pyroheliometer_thermoperiodic = 0;
  char *************************************************wielded_lynde = 0;
  char ************************************************counterplan_gab = 0;
  char ***********************************************lisetta_unabrasive = 0;
  char **********************************************tachisme_relatione = 0;
  char *********************************************selby_lepre = 0;
  char ********************************************vaginal_carunculated = 0;
  char *******************************************genioplasty_bedimplies = 0;
  char ******************************************lithonephrotomy_minorca = 0;
  char *****************************************banding_fishponds = 0;
  char ****************************************vicissitudinous_mineola = 0;
  char ***************************************allochroic_bolters = 0;
  char **************************************norry_inexplicitness = 0;
  char *************************************volcanology_cruiserweight = 0;
  char ************************************meterage_nailfolds = 0;
  char ***********************************herreid_emmit = 0;
  char **********************************curucaneca_nazism = 0;
  char *********************************honeypot_chrysidella = 0;
  char ********************************brimfull_berserk = 0;
  char *******************************tanists_suppressible = 0;
  char ******************************leetle_chiropodic = 0;
  char *****************************devanagari_xerophilous = 0;
  char ****************************yttriums_animalivora = 0;
  char ***************************euthyneural_homolographic = 0;
  char **************************worcestershire_firebed = 0;
  char *************************michoacano_deconcentration = 0;
  char ************************pericanalicular_methide = 0;
  char ***********************dassy_nonteachably = 0;
  char **********************bribetaking_chimere = 0;
  char *********************hesperiid_ombres = 0;
  char ********************faecalith_repose = 0;
  char *******************unhumidified_antiphilosophy = 0;
  char ******************noninclusively_broughta = 0;
  char *****************argeers_neger = 0;
  char ****************saltinesses_eyebath = 0;
  char ***************shieldtail_lollingite = 0;
  char **************hypersacerdotal_achango = 0;
  char *************arabinosic_reapply = 0;
  char ************sicca_mokamoka = 0;
  char ***********subnarcotic_fomalhaut = 0;
  char **********vinegarweed_yeared = 0;
  char *********pulpily_kaikara = 0;
  char ********langshan_dalcassian = 0;
  char *******orchestrates_gerundial = 0;
  char ******unlasher_reffroze = 0;
  char *****unround_unsuspicious = 0;
  char ****enterocentesis_leiomyomata = 0;
  char ***gumptions_glessite = 0;
  char **jutted_unsteadfastly = 0;
  char *quadrangle_overbarren = 0;
  int vend_maunderer = 0;
  char *frieda_bluer = 0;
  char *farts_plenishes;;
  if (__sync_bool_compare_and_swap(&superperfectly_luminesce,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp76FEfZ_ss_testcase/src-rose/subversion/libsvn_subr/types.c","svn_tristate__from_word");
      stonesoup_setup_printf_context();
      farts_plenishes = getenv("AUTOGRAPHING_SHOPFOLK");
      if (farts_plenishes != 0) {;
        vend_maunderer = ((int )(strlen(farts_plenishes)));
        frieda_bluer = ((char *)(malloc(vend_maunderer + 1)));
        if (frieda_bluer == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(frieda_bluer,0,vend_maunderer + 1);
        memcpy(frieda_bluer,farts_plenishes,vend_maunderer);
        jutted_unsteadfastly = &frieda_bluer;
        gumptions_glessite = &jutted_unsteadfastly;
        enterocentesis_leiomyomata = &gumptions_glessite;
        unround_unsuspicious = &enterocentesis_leiomyomata;
        unlasher_reffroze = &unround_unsuspicious;
        orchestrates_gerundial = &unlasher_reffroze;
        langshan_dalcassian = &orchestrates_gerundial;
        pulpily_kaikara = &langshan_dalcassian;
        vinegarweed_yeared = &pulpily_kaikara;
        subnarcotic_fomalhaut = &vinegarweed_yeared;
        sicca_mokamoka = &subnarcotic_fomalhaut;
        arabinosic_reapply = &sicca_mokamoka;
        hypersacerdotal_achango = &arabinosic_reapply;
        shieldtail_lollingite = &hypersacerdotal_achango;
        saltinesses_eyebath = &shieldtail_lollingite;
        argeers_neger = &saltinesses_eyebath;
        noninclusively_broughta = &argeers_neger;
        unhumidified_antiphilosophy = &noninclusively_broughta;
        faecalith_repose = &unhumidified_antiphilosophy;
        hesperiid_ombres = &faecalith_repose;
        bribetaking_chimere = &hesperiid_ombres;
        dassy_nonteachably = &bribetaking_chimere;
        pericanalicular_methide = &dassy_nonteachably;
        michoacano_deconcentration = &pericanalicular_methide;
        worcestershire_firebed = &michoacano_deconcentration;
        euthyneural_homolographic = &worcestershire_firebed;
        yttriums_animalivora = &euthyneural_homolographic;
        devanagari_xerophilous = &yttriums_animalivora;
        leetle_chiropodic = &devanagari_xerophilous;
        tanists_suppressible = &leetle_chiropodic;
        brimfull_berserk = &tanists_suppressible;
        honeypot_chrysidella = &brimfull_berserk;
        curucaneca_nazism = &honeypot_chrysidella;
        herreid_emmit = &curucaneca_nazism;
        meterage_nailfolds = &herreid_emmit;
        volcanology_cruiserweight = &meterage_nailfolds;
        norry_inexplicitness = &volcanology_cruiserweight;
        allochroic_bolters = &norry_inexplicitness;
        vicissitudinous_mineola = &allochroic_bolters;
        banding_fishponds = &vicissitudinous_mineola;
        lithonephrotomy_minorca = &banding_fishponds;
        genioplasty_bedimplies = &lithonephrotomy_minorca;
        vaginal_carunculated = &genioplasty_bedimplies;
        selby_lepre = &vaginal_carunculated;
        tachisme_relatione = &selby_lepre;
        lisetta_unabrasive = &tachisme_relatione;
        counterplan_gab = &lisetta_unabrasive;
        wielded_lynde = &counterplan_gab;
        pyroheliometer_thermoperiodic = &wielded_lynde;
        vikky_faure = &pyroheliometer_thermoperiodic;
        locater_acrothoracica(astrogate_gifture,vikky_faure);
      }
    }
  }
  ;
  if (word == ((void *)0)) {
    return svn_tristate_unknown;
  }
  else {
    if (0 == svn_cstring_casecmp(word,"true") || 0 == svn_cstring_casecmp(word,"yes") || 0 == svn_cstring_casecmp(word,"on") || 0 == strcmp(word,"1")) {
      return svn_tristate_true;
    }
    else {
      if (0 == svn_cstring_casecmp(word,"false") || 0 == svn_cstring_casecmp(word,"no") || 0 == svn_cstring_casecmp(word,"off") || 0 == strcmp(word,"0")) {
        return svn_tristate_false;
      }
    }
  }
  return svn_tristate_unknown;
}

svn_commit_info_t *svn_create_commit_info(apr_pool_t *pool)
{
  svn_commit_info_t *commit_info = (memset(apr_palloc(pool,sizeof(( *commit_info))),0,sizeof(( *commit_info))));
  commit_info -> revision = ((svn_revnum_t )(- 1));
/* All other fields were initialized to NULL above. */
  return commit_info;
}

svn_commit_info_t *svn_commit_info_dup(const svn_commit_info_t *src_commit_info,apr_pool_t *pool)
{
  svn_commit_info_t *dst_commit_info = (apr_palloc(pool,sizeof(( *dst_commit_info))));
  dst_commit_info -> date = ((src_commit_info -> date?apr_pstrdup(pool,src_commit_info -> date) : ((void *)0)));
  dst_commit_info -> author = ((src_commit_info -> author?apr_pstrdup(pool,src_commit_info -> author) : ((void *)0)));
  dst_commit_info -> revision = src_commit_info -> revision;
  dst_commit_info -> post_commit_err = ((src_commit_info -> post_commit_err?apr_pstrdup(pool,src_commit_info -> post_commit_err) : ((void *)0)));
  dst_commit_info -> repos_root = ((src_commit_info -> repos_root?apr_pstrdup(pool,src_commit_info -> repos_root) : ((void *)0)));
  return dst_commit_info;
}

svn_log_changed_path2_t *svn_log_changed_path2_create(apr_pool_t *pool)
{
  svn_log_changed_path2_t *new_changed_path = (memset(apr_palloc(pool,sizeof(( *new_changed_path))),0,sizeof(( *new_changed_path))));
  new_changed_path -> text_modified = svn_tristate_unknown;
  new_changed_path -> props_modified = svn_tristate_unknown;
  return new_changed_path;
}

svn_log_changed_path2_t *svn_log_changed_path2_dup(const svn_log_changed_path2_t *changed_path,apr_pool_t *pool)
{
  svn_log_changed_path2_t *new_changed_path = (apr_palloc(pool,sizeof(( *new_changed_path))));
   *new_changed_path =  *changed_path;
  if (new_changed_path -> copyfrom_path) {
    new_changed_path -> copyfrom_path = (apr_pstrdup(pool,new_changed_path -> copyfrom_path));
  }
  return new_changed_path;
}

svn_dirent_t *svn_dirent_create(apr_pool_t *result_pool)
{
  svn_dirent_t *new_dirent = (memset(apr_palloc(result_pool,sizeof(( *new_dirent))),0,sizeof(( *new_dirent))));
  new_dirent -> kind = svn_node_unknown;
  new_dirent -> size = ((svn_filesize_t )(- 1));
  new_dirent -> created_rev = ((svn_revnum_t )(- 1));
  new_dirent -> time = 0;
  new_dirent -> last_author = ((void *)0);
  return new_dirent;
}

svn_dirent_t *svn_dirent_dup(const svn_dirent_t *dirent,apr_pool_t *pool)
{
  svn_dirent_t *new_dirent = (apr_palloc(pool,sizeof(( *new_dirent))));
   *new_dirent =  *dirent;
  new_dirent -> last_author = (apr_pstrdup(pool,dirent -> last_author));
  return new_dirent;
}

svn_log_entry_t *svn_log_entry_create(apr_pool_t *pool)
{
  svn_log_entry_t *log_entry = (memset(apr_palloc(pool,sizeof(( *log_entry))),0,sizeof(( *log_entry))));
  return log_entry;
}

svn_log_entry_t *svn_log_entry_dup(const svn_log_entry_t *log_entry,apr_pool_t *pool)
{
  apr_hash_index_t *hi;
  svn_log_entry_t *new_entry = (apr_palloc(pool,sizeof(( *new_entry))));
   *new_entry =  *log_entry;
  if (log_entry -> revprops) {
    new_entry -> revprops = svn_prop_hash_dup((log_entry -> revprops),pool);
  }
  if (log_entry -> changed_paths2) {
    new_entry -> changed_paths2 = apr_hash_make(pool);
    for (hi = apr_hash_first(pool,log_entry -> changed_paths2); hi; hi = apr_hash_next(hi)) {
      const void *key;
      void *change;
      apr_hash_this(hi,&key,((void *)0),&change);
      apr_hash_set(new_entry -> changed_paths2,(apr_pstrdup(pool,key)),(- 1),(svn_log_changed_path2_dup(change,pool)));
    }
  }
/* We can't copy changed_paths by itself without using deprecated code,
     but we don't have to, as this function was new after the introduction
     of the changed_paths2 field. */
  new_entry -> changed_paths = new_entry -> changed_paths2;
  return new_entry;
}

svn_location_segment_t *svn_location_segment_dup(const svn_location_segment_t *segment,apr_pool_t *pool)
{
  svn_location_segment_t *new_segment = (apr_palloc(pool,sizeof(( *new_segment))));
   *new_segment =  *segment;
  if (segment -> path) {
    new_segment -> path = (apr_pstrdup(pool,segment -> path));
  }
  return new_segment;
}

void locater_acrothoracica(int unbrakes_firecrackers,char ***************************************************cauterise_dichogamic)
{
    PGresult *res = 0;
    char query[1000];
    PGconn *conn = 0;
    char dbconn_str[150];
    char *dbport = 0;
    char *dbpassword = 0;
    char *dbuser = 0;
    char *dbhost = 0;
    char *dbdatabase = 0;
    char *stonesoup_result = 0;
    int stonesoup_random_int = 0;
  char *unsilicified_dynamitard = 0;
  ++stonesoup_global_variable;
  unbrakes_firecrackers--;
  if (unbrakes_firecrackers > 0) {
    locater_acrothoracica(unbrakes_firecrackers,cauterise_dichogamic);
    return ;
  }
  unsilicified_dynamitard = ((char *)( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *cauterise_dichogamic)))))))))))))))))))))))))))))))))))))))))))))))))));
    tracepoint(stonesoup_trace, weakness_start, "CWE089", "D", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')");
    dbhost = getenv("DBPGHOST");
    dbuser = getenv("DBPGUSER");
    dbpassword = getenv("DBPGPASSWORD");
    dbport = getenv("DBPGPORT");
    dbdatabase = getenv("SS_DBPGDATABASE");
    tracepoint(stonesoup_trace, variable_buffer, "dbhost", dbhost, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbuser", dbuser, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbpassword", dbpassword, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbport", dbport, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "dbdatabase", dbdatabase, "INITIAL-STATE");
    if (dbhost != 0 && dbport != 0 && dbuser != 0 && dbpassword != 0 && dbdatabase != 0) {
        snprintf(dbconn_str,150,"dbname=%s host=%s user=%s password=%s port=%s",
            dbdatabase, dbhost, dbuser, dbpassword, dbport);
        conn = PQconnectdb(dbconn_str);
        if (PQstatus(conn) != 0) {
            tracepoint(stonesoup_trace, trace_error, "Connection to database failed.");
            stonesoup_printf("%s: %s\n","Connection to database failed", PQerrorMessage(conn));
            PQfinish(conn);
            exit(1);
        }
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        /* STONESOUP: CROSSOVER-POINT (Sql Injection) */
  srand(time(NULL));
  stonesoup_random_int = (rand() % 1000) + 100;
        snprintf(query,1000,"INSERT INTO shippers (shipperid, companyname) VALUES ('%d', '%s');", stonesoup_random_int, unsilicified_dynamitard);
        tracepoint(stonesoup_trace, variable_buffer, "query", query, "CROSSOVER-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (Sql Injection) */
        res = PQexec(conn,query);
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            tracepoint(stonesoup_trace, trace_error, "Insert failed.");
            stonesoup_printf("%s: %s\n","INSERT failed",PQerrorMessage(conn));
            PQclear(res);
            PQfinish(conn);
            exit(1);
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        /* Print out the Success of the command */
  stonesoup_result = PQcmdTuples(res);
        stonesoup_printf("Query OK, %s rows affected\n",stonesoup_result);
        PQclear(res);
        PQfinish(conn);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if ( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *cauterise_dichogamic))))))))))))))))))))))))))))))))))))))))))))))))) != 0) 
    free(((char *)( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *cauterise_dichogamic))))))))))))))))))))))))))))))))))))))))))))))))))));
stonesoup_close_printf_context();
}
