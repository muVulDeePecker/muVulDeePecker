/*-------------------------------------------------------------------------
 *
 * hashfn.c
 *		Hash functions for use in dynahash.c hashtables
 *
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/hash/hashfn.c
 *
 * NOTES
 *	  It is expected that every bit of a hash function's 32-bit result is
 *	  as random as every other; failure to ensure this is likely to lead
 *	  to poor performance of hash tables.  In most cases a hash
 *	  function should use hash_any() or its variant hash_uint32().
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "access/hash.h"
/*
 * string_hash: hash function for keys that are NUL-terminated strings.
 *
 * NOTE: this is the default hash function if none is specified.
 */
#include <sys/stat.h> 
#include <stonesoup/stonesoup_trace.h> 
int hickishness_electrogalvanic = 0;
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
void hemoclasis_fidley(char *hedgehogs_confustication);
struct stonesoup_struct_data {
  char *buffer_member;
  unsigned short size_member;
};
struct stonesoup_struct_data *stonesoup_init_data(long number_param)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpT2mrJC_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c", "stonesoup_init_data");
  struct stonesoup_struct_data *init_data_ptr = 0;
  init_data_ptr = ((struct stonesoup_struct_data *)(malloc(sizeof(struct stonesoup_struct_data ))));
  if (init_data_ptr == 0)
    return 0;
  init_data_ptr -> size_member = 0;
  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Numerical Truncation Error) */
  init_data_ptr -> size_member = number_param;
  init_data_ptr -> buffer_member = ((char *)(malloc(sizeof(char ) * init_data_ptr -> size_member)));
  tracepoint(stonesoup_trace, variable_signed_integral, "number_param", number_param, &number_param, "CROSSOVER-STATE");
  tracepoint(stonesoup_trace, variable_signed_integral, "(init_data_ptr->size_member)", (init_data_ptr->size_member), &(init_data_ptr->size_member), "CROSSOVER-STATE");
  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
  if (init_data_ptr -> buffer_member == 0) {
    free(init_data_ptr);
    return 0;
  }
  memset(init_data_ptr -> buffer_member,'a',init_data_ptr -> size_member);
  init_data_ptr -> buffer_member[init_data_ptr -> size_member - 1] = 0;
  return init_data_ptr;
}

uint32 string_hash(const void *key,Size keysize)
{
/*
	 * If the string exceeds keysize-1 bytes, we want to hash only that many,
	 * because when it is copied into the hash table it will be truncated at
	 * that length.
	 */
  Size s_len = strlen(((const char *)key));
  s_len = (s_len < keysize - 1?s_len : keysize - 1);
  return (uint32 )(((Datum )(hash_any(((const unsigned char *)key),((int )s_len)))) & 0xffffffff);
}
/*
 * tag_hash: hash function for fixed-size tag values
 */

uint32 tag_hash(const void *key,Size keysize)
{
  return (uint32 )(((Datum )(hash_any(((const unsigned char *)key),((int )keysize)))) & 0xffffffff);
}
#define IMMOBILE_NONARGUABLE(x) hemoclasis_fidley((char *) x)
/*
 * oid_hash: hash function for keys that are OIDs
 *
 * (tag_hash works for this case too, but is slower)
 */

uint32 oid_hash(const void *key,Size keysize)
{
  char *empestic_untaking = 0;
  int **************************************************heterolalia_basidigitale = 0;
  int *************************************************amphithere_splenatrophia = 0;
  int ************************************************betalk_stechados = 0;
  int ***********************************************aftaba_violuric = 0;
  int **********************************************piquia_achimelech = 0;
  int *********************************************dhak_duncan = 0;
  int ********************************************suffisance_subattenuated = 0;
  int *******************************************tamandua_urmston = 0;
  int ******************************************gayla_chloridated = 0;
  int *****************************************tuberose_befavour = 0;
  int ****************************************antipoenus_acceleration = 0;
  int ***************************************bollixes_ftz = 0;
  int **************************************draconianism_pseudodox = 0;
  int *************************************dishellenize_neuratrophic = 0;
  int ************************************sourveld_albigensian = 0;
  int ***********************************beforesaid_nonconfiding = 0;
  int **********************************meteorization_chundari = 0;
  int *********************************harlem_pudibundity = 0;
  int ********************************yade_hailes = 0;
  int *******************************kanone_incremating = 0;
  int ******************************microsomial_matuta = 0;
  int *****************************knobnoster_mistressless = 0;
  int ****************************communized_superaqual = 0;
  int ***************************laiose_dogs = 0;
  int **************************uncompared_timbuktu = 0;
  int *************************lawsonville_forehoofs = 0;
  int ************************naphthalise_kanawha = 0;
  int ***********************chrysanthemum_pedately = 0;
  int **********************babson_beadswomen = 0;
  int *********************moqui_estevan = 0;
  int ********************supermoisten_stockstone = 0;
  int *******************spherome_overwarily = 0;
  int ******************nacre_boxfishes = 0;
  int *****************frizer_intubatting = 0;
  int ****************jingo_seesawing = 0;
  int ***************counts_slinkskin = 0;
  int **************chaffinch_perotin = 0;
  int *************reciprocate_geneva = 0;
  int ************keest_carbonimeter = 0;
  int ***********uncomplemented_thetis = 0;
  int **********subcutaneously_agone = 0;
  int *********ochnaceae_segregated = 0;
  int ********plenipotential_aneurysm = 0;
  int *******phlebolith_dispraising = 0;
  int ******unrelatable_bachelorize = 0;
  int *****wappinger_cytoplasmic = 0;
  int ****teleprocessing_ochroleucous = 0;
  int ***bealing_felis = 0;
  int **barragon_victorianly = 0;
  int *warranting_monkeys = 0;
  int soutanes_gds;
  char *penalising_disappoint[10] = {0};
  char *ventrals_prosely;;
  if (__sync_bool_compare_and_swap(&hickishness_electrogalvanic,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpT2mrJC_ss_testcase/src-rose/src/backend/utils/hash/hashfn.c","oid_hash");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&ventrals_prosely,"TIGGER_ORRIN");
      if (ventrals_prosely != 0) {;
        soutanes_gds = 5;
        warranting_monkeys = &soutanes_gds;
        barragon_victorianly = &warranting_monkeys;
        bealing_felis = &barragon_victorianly;
        teleprocessing_ochroleucous = &bealing_felis;
        wappinger_cytoplasmic = &teleprocessing_ochroleucous;
        unrelatable_bachelorize = &wappinger_cytoplasmic;
        phlebolith_dispraising = &unrelatable_bachelorize;
        plenipotential_aneurysm = &phlebolith_dispraising;
        ochnaceae_segregated = &plenipotential_aneurysm;
        subcutaneously_agone = &ochnaceae_segregated;
        uncomplemented_thetis = &subcutaneously_agone;
        keest_carbonimeter = &uncomplemented_thetis;
        reciprocate_geneva = &keest_carbonimeter;
        chaffinch_perotin = &reciprocate_geneva;
        counts_slinkskin = &chaffinch_perotin;
        jingo_seesawing = &counts_slinkskin;
        frizer_intubatting = &jingo_seesawing;
        nacre_boxfishes = &frizer_intubatting;
        spherome_overwarily = &nacre_boxfishes;
        supermoisten_stockstone = &spherome_overwarily;
        moqui_estevan = &supermoisten_stockstone;
        babson_beadswomen = &moqui_estevan;
        chrysanthemum_pedately = &babson_beadswomen;
        naphthalise_kanawha = &chrysanthemum_pedately;
        lawsonville_forehoofs = &naphthalise_kanawha;
        uncompared_timbuktu = &lawsonville_forehoofs;
        laiose_dogs = &uncompared_timbuktu;
        communized_superaqual = &laiose_dogs;
        knobnoster_mistressless = &communized_superaqual;
        microsomial_matuta = &knobnoster_mistressless;
        kanone_incremating = &microsomial_matuta;
        yade_hailes = &kanone_incremating;
        harlem_pudibundity = &yade_hailes;
        meteorization_chundari = &harlem_pudibundity;
        beforesaid_nonconfiding = &meteorization_chundari;
        sourveld_albigensian = &beforesaid_nonconfiding;
        dishellenize_neuratrophic = &sourveld_albigensian;
        draconianism_pseudodox = &dishellenize_neuratrophic;
        bollixes_ftz = &draconianism_pseudodox;
        antipoenus_acceleration = &bollixes_ftz;
        tuberose_befavour = &antipoenus_acceleration;
        gayla_chloridated = &tuberose_befavour;
        tamandua_urmston = &gayla_chloridated;
        suffisance_subattenuated = &tamandua_urmston;
        dhak_duncan = &suffisance_subattenuated;
        piquia_achimelech = &dhak_duncan;
        aftaba_violuric = &piquia_achimelech;
        betalk_stechados = &aftaba_violuric;
        amphithere_splenatrophia = &betalk_stechados;
        heterolalia_basidigitale = &amphithere_splenatrophia;
        penalising_disappoint[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *heterolalia_basidigitale)))))))))))))))))))))))))))))))))))))))))))))))))] = ventrals_prosely;
        empestic_untaking = penalising_disappoint[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *heterolalia_basidigitale)))))))))))))))))))))))))))))))))))))))))))))))))];
	IMMOBILE_NONARGUABLE(empestic_untaking);
      }
    }
  }
  ;
  ;
  return (uint32 )(((Datum )(hash_uint32(((uint32 )( *((const Oid *)key)))))) & 0xffffffff);
}
/*
 * bitmap_hash: hash function for keys that are (pointers to) Bitmapsets
 *
 * Note: don't forget to specify bitmap_match as the match function!
 */

uint32 bitmap_hash(const void *key,Size keysize)
{
  ;
  return bms_hash_value( *((const Bitmapset *const *)key));
}
/*
 * bitmap_match: match function to use with bitmap_hash
 */

int bitmap_match(const void *key1,const void *key2,Size keysize)
{
  ;
  return !bms_equal( *((const Bitmapset *const *)key1), *((const Bitmapset *const *)key2));
}

void hemoclasis_fidley(char *hedgehogs_confustication)
{
    long stonesoup_number;
    struct stonesoup_struct_data *stonesoup_data = 0;
  char *unthroaty_relocating = 0;
  ++stonesoup_global_variable;;
  unthroaty_relocating = ((char *)hedgehogs_confustication);
    tracepoint(stonesoup_trace, weakness_start, "CWE197", "A", "Numeric Truncation Error");
    stonesoup_number = strtol(unthroaty_relocating,0U,10);
    if (stonesoup_number > 0) {
        stonesoup_data = stonesoup_init_data(stonesoup_number);
        if (stonesoup_data != 0) {
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Numerical Truncation Error) */
          memset(stonesoup_data -> buffer_member, 98, stonesoup_number);
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
          stonesoup_data -> buffer_member[stonesoup_number - 1] = 0;
          stonesoup_printf("%s\n", stonesoup_data -> buffer_member);
          if (stonesoup_data -> buffer_member != 0U)
            free(stonesoup_data -> buffer_member);
          if (stonesoup_data != 0U)
            free(stonesoup_data);
        }
    } else {
        stonesoup_printf("Input is less than or equal to 0\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (hedgehogs_confustication != 0) 
    free(((char *)hedgehogs_confustication));
stonesoup_close_printf_context();
}
