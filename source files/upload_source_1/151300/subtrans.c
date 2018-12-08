/*-------------------------------------------------------------------------
 *
 * subtrans.c
 *		PostgreSQL subtransaction-log manager
 *
 * The pg_subtrans manager is a pg_clog-like manager that stores the parent
 * transaction Id for each transaction.  It is a fundamental part of the
 * nested transactions implementation.	A main transaction has a parent
 * of InvalidTransactionId, and each subtransaction has its immediate parent.
 * The tree can easily be walked from child to parent, but not in the
 * opposite direction.
 *
 * This code is based on clog.c, but the robustness requirements
 * are completely different from pg_clog, because we only need to remember
 * pg_subtrans information for currently-open transactions.  Thus, there is
 * no need to preserve data over a crash and restart.
 *
 * There are no XLOG interactions since we do not care about preserving
 * data across crashes.  During database startup, we simply force the
 * currently-active page of SUBTRANS to zeroes.
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/transam/subtrans.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "access/slru.h"
#include "access/subtrans.h"
#include "access/transam.h"
#include "pg_trace.h"
#include "utils/snapmgr.h"
/*
 * Defines for SubTrans page sizes.  A page is the same BLCKSZ as is used
 * everywhere else in Postgres.
 *
 * Note: because TransactionIds are 32 bits and wrap around at 0xFFFFFFFF,
 * SubTrans page numbering also wraps around at
 * 0xFFFFFFFF/SUBTRANS_XACTS_PER_PAGE, and segment numbering at
 * 0xFFFFFFFF/SUBTRANS_XACTS_PER_PAGE/SLRU_SEGMENTS_PER_PAGE.  We need take no
 * explicit notice of that fact in this module, except when comparing segment
 * and page numbers in TruncateSUBTRANS (see SubTransPagePrecedes).
 */
/* We need four bytes per xact */
#define SUBTRANS_XACTS_PER_PAGE (BLCKSZ / sizeof(TransactionId))
#define TransactionIdToPage(xid) ((xid) / (TransactionId) SUBTRANS_XACTS_PER_PAGE)
#define TransactionIdToEntry(xid) ((xid) % (TransactionId) SUBTRANS_XACTS_PER_PAGE)
/*
 * Link to shared-memory data structures for SUBTRANS control
 */
#include <sys/stat.h> 
#include <stonesoup/stonesoup_trace.h> 
static SlruCtlData SubTransCtlData;
#define SubTransCtl  (&SubTransCtlData)
static int ZeroSUBTRANSPage(int pageno);
static bool SubTransPagePrecedes(int page1,int page2);
/*
 * Record the parent of a subtransaction in the subtrans log.
 *
 * In some cases we may need to overwrite an existing value.
 */
int reincapable_yerevan = 0;
int stonesoup_global_variable;

union undiscouraged_dhourras 
{
  char *masjids_skiapodous;
  double norseman_positions;
  char *chungking_seniorship;
  char serbonian_enthronising;
  int somedeal_kalendarial;
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
void distortive_superelegancy(union undiscouraged_dhourras **********amphipyrenin_cystenchyma);
void durhamville_unitarist(union undiscouraged_dhourras **********prela_ocyroidae);
void karluk_herding(union undiscouraged_dhourras **********aor_midas);
void outsnore_underprop(union undiscouraged_dhourras **********premaintain_acrocyst);
void ammonite_commistion(union undiscouraged_dhourras **********kutenai_overinflating);
void woodwind_kitchenward(union undiscouraged_dhourras **********inkstands_degas);
void harquebuse_baronetizing(union undiscouraged_dhourras **********latrobite_groupoids);
void babelised_creston(union undiscouraged_dhourras **********underwrite_implore);
void scrobicula_unwingable(union undiscouraged_dhourras **********tirralirra_calendry);
void camphor_interaccused(union undiscouraged_dhourras **********gauds_fibro);
void phagedaenous_epergnes(union undiscouraged_dhourras **********wawa_gravelled);
void prillion_inerroneous(union undiscouraged_dhourras **********uncs_anzanite);
void degausser_luniest(union undiscouraged_dhourras **********patt_sycophantly);
void puritanlike_fearless(union undiscouraged_dhourras **********outlove_coercions);
void baze_shoyus(union undiscouraged_dhourras **********upstare_laputically);
void savonarolist_aion(union undiscouraged_dhourras **********lawley_choroid);
void bever_leptospira(union undiscouraged_dhourras **********habenulae_willer);
void recreate_greenest(union undiscouraged_dhourras **********unreversible_surmiser);
void hairbrained_taimyrite(union undiscouraged_dhourras **********byrlady_musit);
void indazole_millstream(union undiscouraged_dhourras **********moveability_cacodemoniac);
void calves_phrenopathic(union undiscouraged_dhourras **********significatory_pinette);
void coronitis_sausinger(union undiscouraged_dhourras **********unhyphenable_sillometer);
void bunnies_haptophor(union undiscouraged_dhourras **********benia_nanuet);
void tattoos_meill(union undiscouraged_dhourras **********gres_feudalizable);
void flatten_elatives(union undiscouraged_dhourras **********clochette_autoecic);
void viole_chlorodizing(union undiscouraged_dhourras **********unmitigatedly_streak);
void milquetoast_genetoid(union undiscouraged_dhourras **********pyridoxal_octaploid);
void sycamines_dissertations(union undiscouraged_dhourras **********frogleg_memling);
void nonconfiding_amsonia(union undiscouraged_dhourras **********endenization_overiodized);
void mesal_unseductively(union undiscouraged_dhourras **********xerasia_ilo);
void kinetophone_factionism(union undiscouraged_dhourras **********polishedness_shuck);
void essexville_faddishness(union undiscouraged_dhourras **********overprizing_kotta);
void kangayam_jermoonal(union undiscouraged_dhourras **********claymore_overinfluenced);
void indexically_burkes(union undiscouraged_dhourras **********precaval_limnery);
void guinea_repellance(union undiscouraged_dhourras **********nonaccommodable_philosophobia);
void kingsize_fulham(union undiscouraged_dhourras **********corroboratively_bulldozed);
void decays_arkite(union undiscouraged_dhourras **********absalom_unantlered);
void postdepressive_jackhammers(union undiscouraged_dhourras **********hoarsen_guimar);
void megalospheric_abrasions(union undiscouraged_dhourras **********oregano_submorphous);
void darlington_musher(union undiscouraged_dhourras **********scribbleable_goatfish);
void acquiescing_riverboats(union undiscouraged_dhourras **********nonmanneristic_shaikhi);
void tilletiaceous_expropriated(union undiscouraged_dhourras **********inkier_janker);
void shapable_antievolution(union undiscouraged_dhourras **********trotyl_unhesitatively);
void bicoloured_unlingering(union undiscouraged_dhourras **********antimonic_lucretius);
void manichaeist_annalist(union undiscouraged_dhourras **********sintoc_thrombotic);
void hemidactylous_burghs(union undiscouraged_dhourras **********unconjugated_overlard);
void dentistical_capillus(union undiscouraged_dhourras **********phelonions_catano);
void bosker_sizy(union undiscouraged_dhourras **********ceruminous_crabbiest);
void tiberian_geatas(union undiscouraged_dhourras **********msee_degumming);
void boarship_gto(union undiscouraged_dhourras **********arrio_liggitt);
struct stonesoup_struct {
    void (*stonesoup_function_ptr_1)();
    unsigned int stonesoup_input_num;
    void (*stonesoup_function_ptr_2)();
};
void stonesoup_function() {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpr6WkIv_ss_testcase/src-rose/src/backend/access/transam/subtrans.c", "stonesoup_function");
}

void SubTransSetParent(TransactionId xid,TransactionId parent,bool overwriteOK)
{
  int pageno = (xid / ((TransactionId )(8192 / sizeof(TransactionId ))));
  int entryno = (xid % ((TransactionId )(8192 / sizeof(TransactionId ))));
  int slotno;
  TransactionId *ptr;
  ;
  LWLockAcquire(SubtransControlLock,LW_EXCLUSIVE);
  slotno = SimpleLruReadPage(&SubTransCtlData,pageno,((bool )1),xid);
  ptr = ((TransactionId *)(&SubTransCtlData) -> shared -> page_buffer[slotno]);
  ptr += entryno;
/* Current state should be 0 */
  ;
   *ptr = parent;
  (&SubTransCtlData) -> shared -> page_dirty[slotno] = ((bool )1);
  LWLockRelease(SubtransControlLock);
}
/*
 * Interrogate the parent of a transaction in the subtrans log.
 */

TransactionId SubTransGetParent(TransactionId xid)
{
  int pageno = (xid / ((TransactionId )(8192 / sizeof(TransactionId ))));
  int entryno = (xid % ((TransactionId )(8192 / sizeof(TransactionId ))));
  int slotno;
  TransactionId *ptr;
  TransactionId parent;
/* Can't ask about stuff that might not be around anymore */
  ;
/* Bootstrap and frozen XIDs have no parent */
  if (!(xid >= ((TransactionId )3))) {
    return (TransactionId )0;
  }
/* lock is acquired by SimpleLruReadPage_ReadOnly */
  slotno = SimpleLruReadPage_ReadOnly(&SubTransCtlData,pageno,xid);
  ptr = ((TransactionId *)(&SubTransCtlData) -> shared -> page_buffer[slotno]);
  ptr += entryno;
  parent =  *ptr;
  LWLockRelease(SubtransControlLock);
  return parent;
}
/*
 * SubTransGetTopmostTransaction
 *
 * Returns the topmost transaction of the given transaction id.
 *
 * Because we cannot look back further than TransactionXmin, it is possible
 * that this function will lie and return an intermediate subtransaction ID
 * instead of the true topmost parent ID.  This is OK, because in practice
 * we only care about detecting whether the topmost parent is still running
 * or is part of a current snapshot's list of still-running transactions.
 * Therefore, any XID before TransactionXmin is as good as any other.
 */

TransactionId SubTransGetTopmostTransaction(TransactionId xid)
{
  TransactionId parentXid = xid;
  TransactionId previousXid = xid;
/* Can't ask about stuff that might not be around anymore */
  ;
  while(parentXid != ((TransactionId )0)){
    previousXid = parentXid;
    if (TransactionIdPrecedes(parentXid,TransactionXmin)) {
      break; 
    }
    parentXid = SubTransGetParent(parentXid);
  }
  ;
  return previousXid;
}
/*
 * Initialization of shared memory for SUBTRANS
 */

Size SUBTRANSShmemSize()
{
  return SimpleLruShmemSize(32,0);
}

void SUBTRANSShmemInit()
{
  (&SubTransCtlData) -> PagePrecedes = SubTransPagePrecedes;
  SimpleLruInit(&SubTransCtlData,"SUBTRANS Ctl",32,0,SubtransControlLock,"pg_subtrans");
/* Override default assumption that writes should be fsync'd */
  (&SubTransCtlData) -> do_fsync = ((bool )0);
}
/*
 * This func must be called ONCE on system install.  It creates
 * the initial SUBTRANS segment.  (The SUBTRANS directory is assumed to
 * have been created by the initdb shell script, and SUBTRANSShmemInit
 * must have been called already.)
 *
 * Note: it's not really necessary to create the initial segment now,
 * since slru.c would create it on first write anyway.	But we may as well
 * do it to be sure the directory is set up correctly.
 */

void BootStrapSUBTRANS()
{
  int slotno;
  LWLockAcquire(SubtransControlLock,LW_EXCLUSIVE);
/* Create and zero the first page of the subtrans log */
  slotno = ZeroSUBTRANSPage(0);
/* Make sure it's written out */
  SimpleLruWritePage(&SubTransCtlData,slotno);
  ;
  LWLockRelease(SubtransControlLock);
}
/*
 * Initialize (or reinitialize) a page of SUBTRANS to zeroes.
 *
 * The page is not actually written, just set up in shared memory.
 * The slot number of the new page is returned.
 *
 * Control lock must be held at entry, and will be held at exit.
 */

static int ZeroSUBTRANSPage(int pageno)
{
  return SimpleLruZeroPage(&SubTransCtlData,pageno);
}
/*
 * This must be called ONCE during postmaster or standalone-backend startup,
 * after StartupXLOG has initialized ShmemVariableCache->nextXid.
 *
 * oldestActiveXID is the oldest XID of any prepared transaction, or nextXid
 * if there are none.
 */

void StartupSUBTRANS(TransactionId oldestActiveXID)
{
  union undiscouraged_dhourras **********stationariness_fulvid = 0;
  union undiscouraged_dhourras *********aleochara_ribbands = 0;
  union undiscouraged_dhourras ********cenesthesis_coloristically = 0;
  union undiscouraged_dhourras *******sublicensing_trioxid = 0;
  union undiscouraged_dhourras ******slangkop_inauspicate = 0;
  union undiscouraged_dhourras *****ominously_phobus = 0;
  union undiscouraged_dhourras ****conn_denunciant = 0;
  union undiscouraged_dhourras ***alniresinol_syncopated = 0;
  union undiscouraged_dhourras **basinasial_areopagitic = 0;
  union undiscouraged_dhourras *mima_idyllists = 0;
  union undiscouraged_dhourras esparto_thoroughsped = {0};
  union undiscouraged_dhourras rankine_belah;
  char *anisamide_cupromanganese;
  int startPage;
  int endPage;
  if (__sync_bool_compare_and_swap(&reincapable_yerevan,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpr6WkIv_ss_testcase/src-rose/src/backend/access/transam/subtrans.c","StartupSUBTRANS");
      stonesoup_setup_printf_context();
      anisamide_cupromanganese = getenv("CONTIGUITIES_FRIS");
      if (anisamide_cupromanganese != 0) {;
        rankine_belah . masjids_skiapodous = anisamide_cupromanganese;
        mima_idyllists = &rankine_belah;
        basinasial_areopagitic = &mima_idyllists;
        alniresinol_syncopated = &basinasial_areopagitic;
        conn_denunciant = &alniresinol_syncopated;
        ominously_phobus = &conn_denunciant;
        slangkop_inauspicate = &ominously_phobus;
        sublicensing_trioxid = &slangkop_inauspicate;
        cenesthesis_coloristically = &sublicensing_trioxid;
        aleochara_ribbands = &cenesthesis_coloristically;
        stationariness_fulvid = &aleochara_ribbands;
        distortive_superelegancy(stationariness_fulvid);
      }
    }
  }
/*
	 * Since we don't expect pg_subtrans to be valid across crashes, we
	 * initialize the currently-active page(s) to zeroes during startup.
	 * Whenever we advance into a new page, ExtendSUBTRANS will likewise zero
	 * the new page without regard to whatever was previously on disk.
	 */
  LWLockAcquire(SubtransControlLock,LW_EXCLUSIVE);
  startPage = (oldestActiveXID / ((TransactionId )(8192 / sizeof(TransactionId ))));
  endPage = (ShmemVariableCache -> nextXid / ((TransactionId )(8192 / sizeof(TransactionId ))));
  while(startPage != endPage){
    (void )(ZeroSUBTRANSPage(startPage));
    startPage++;
  }
  (void )(ZeroSUBTRANSPage(startPage));
  LWLockRelease(SubtransControlLock);
}
/*
 * This must be called ONCE during postmaster or standalone-backend shutdown
 */

void ShutdownSUBTRANS()
{
/*
	 * Flush dirty SUBTRANS pages to disk
	 *
	 * This is not actually necessary from a correctness point of view. We do
	 * it merely as a debugging aid.
	 */
  ;
  SimpleLruFlush(&SubTransCtlData,((bool )0));
  ;
}
/*
 * Perform a checkpoint --- either during shutdown, or on-the-fly
 */

void CheckPointSUBTRANS()
{
/*
	 * Flush dirty SUBTRANS pages to disk
	 *
	 * This is not actually necessary from a correctness point of view. We do
	 * it merely to improve the odds that writing of dirty pages is done by
	 * the checkpoint process and not by backends.
	 */
  ;
  SimpleLruFlush(&SubTransCtlData,((bool )1));
  ;
}
/*
 * Make sure that SUBTRANS has room for a newly-allocated XID.
 *
 * NB: this is called while holding XidGenLock.  We want it to be very fast
 * most of the time; even when it's not so fast, no actual I/O need happen
 * unless we're forced to write out a dirty subtrans page to make room
 * in shared memory.
 */

void ExtendSUBTRANS(TransactionId newestXact)
{
  int pageno;
/*
	 * No work except at first XID of a page.  But beware: just after
	 * wraparound, the first XID of page zero is FirstNormalTransactionId.
	 */
  if (newestXact % ((TransactionId )(8192 / sizeof(TransactionId ))) != 0 && !(newestXact == ((TransactionId )3))) {
    return ;
  }
  pageno = (newestXact / ((TransactionId )(8192 / sizeof(TransactionId ))));
  LWLockAcquire(SubtransControlLock,LW_EXCLUSIVE);
/* Zero the page */
  ZeroSUBTRANSPage(pageno);
  LWLockRelease(SubtransControlLock);
}
/*
 * Remove all SUBTRANS segments before the one holding the passed transaction ID
 *
 * This is normally called during checkpoint, with oldestXact being the
 * oldest TransactionXmin of any running transaction.
 */

void TruncateSUBTRANS(TransactionId oldestXact)
{
  int cutoffPage;
/*
	 * The cutoff point is the start of the segment containing oldestXact. We
	 * pass the *page* containing oldestXact to SimpleLruTruncate.
	 */
  cutoffPage = (oldestXact / ((TransactionId )(8192 / sizeof(TransactionId ))));
  SimpleLruTruncate(&SubTransCtlData,cutoffPage);
}
/*
 * Decide which of two SUBTRANS page numbers is "older" for truncation purposes.
 *
 * We need to use comparison of TransactionIds here in order to do the right
 * thing with wraparound XID arithmetic.  However, if we are asked about
 * page number zero, we don't want to hand InvalidTransactionId to
 * TransactionIdPrecedes: it'll get weird about permanent xact IDs.  So,
 * offset both xids by FirstNormalTransactionId to avoid that.
 */

static bool SubTransPagePrecedes(int page1,int page2)
{
  TransactionId xid1;
  TransactionId xid2;
  xid1 = (((TransactionId )page1) * (8192 / sizeof(TransactionId )));
  xid1 += ((TransactionId )3);
  xid2 = (((TransactionId )page2) * (8192 / sizeof(TransactionId )));
  xid2 += ((TransactionId )3);
  return TransactionIdPrecedes(xid1,xid2);
}

void distortive_superelegancy(union undiscouraged_dhourras **********amphipyrenin_cystenchyma)
{
  ++stonesoup_global_variable;;
  durhamville_unitarist(amphipyrenin_cystenchyma);
}

void durhamville_unitarist(union undiscouraged_dhourras **********prela_ocyroidae)
{
  ++stonesoup_global_variable;;
  karluk_herding(prela_ocyroidae);
}

void karluk_herding(union undiscouraged_dhourras **********aor_midas)
{
  ++stonesoup_global_variable;;
  outsnore_underprop(aor_midas);
}

void outsnore_underprop(union undiscouraged_dhourras **********premaintain_acrocyst)
{
  ++stonesoup_global_variable;;
  ammonite_commistion(premaintain_acrocyst);
}

void ammonite_commistion(union undiscouraged_dhourras **********kutenai_overinflating)
{
  ++stonesoup_global_variable;;
  woodwind_kitchenward(kutenai_overinflating);
}

void woodwind_kitchenward(union undiscouraged_dhourras **********inkstands_degas)
{
  ++stonesoup_global_variable;;
  harquebuse_baronetizing(inkstands_degas);
}

void harquebuse_baronetizing(union undiscouraged_dhourras **********latrobite_groupoids)
{
  ++stonesoup_global_variable;;
  babelised_creston(latrobite_groupoids);
}

void babelised_creston(union undiscouraged_dhourras **********underwrite_implore)
{
  ++stonesoup_global_variable;;
  scrobicula_unwingable(underwrite_implore);
}

void scrobicula_unwingable(union undiscouraged_dhourras **********tirralirra_calendry)
{
  ++stonesoup_global_variable;;
  camphor_interaccused(tirralirra_calendry);
}

void camphor_interaccused(union undiscouraged_dhourras **********gauds_fibro)
{
  ++stonesoup_global_variable;;
  phagedaenous_epergnes(gauds_fibro);
}

void phagedaenous_epergnes(union undiscouraged_dhourras **********wawa_gravelled)
{
  ++stonesoup_global_variable;;
  prillion_inerroneous(wawa_gravelled);
}

void prillion_inerroneous(union undiscouraged_dhourras **********uncs_anzanite)
{
  ++stonesoup_global_variable;;
  degausser_luniest(uncs_anzanite);
}

void degausser_luniest(union undiscouraged_dhourras **********patt_sycophantly)
{
  ++stonesoup_global_variable;;
  puritanlike_fearless(patt_sycophantly);
}

void puritanlike_fearless(union undiscouraged_dhourras **********outlove_coercions)
{
  ++stonesoup_global_variable;;
  baze_shoyus(outlove_coercions);
}

void baze_shoyus(union undiscouraged_dhourras **********upstare_laputically)
{
  ++stonesoup_global_variable;;
  savonarolist_aion(upstare_laputically);
}

void savonarolist_aion(union undiscouraged_dhourras **********lawley_choroid)
{
  ++stonesoup_global_variable;;
  bever_leptospira(lawley_choroid);
}

void bever_leptospira(union undiscouraged_dhourras **********habenulae_willer)
{
  ++stonesoup_global_variable;;
  recreate_greenest(habenulae_willer);
}

void recreate_greenest(union undiscouraged_dhourras **********unreversible_surmiser)
{
  ++stonesoup_global_variable;;
  hairbrained_taimyrite(unreversible_surmiser);
}

void hairbrained_taimyrite(union undiscouraged_dhourras **********byrlady_musit)
{
  ++stonesoup_global_variable;;
  indazole_millstream(byrlady_musit);
}

void indazole_millstream(union undiscouraged_dhourras **********moveability_cacodemoniac)
{
  ++stonesoup_global_variable;;
  calves_phrenopathic(moveability_cacodemoniac);
}

void calves_phrenopathic(union undiscouraged_dhourras **********significatory_pinette)
{
  ++stonesoup_global_variable;;
  coronitis_sausinger(significatory_pinette);
}

void coronitis_sausinger(union undiscouraged_dhourras **********unhyphenable_sillometer)
{
  ++stonesoup_global_variable;;
  bunnies_haptophor(unhyphenable_sillometer);
}

void bunnies_haptophor(union undiscouraged_dhourras **********benia_nanuet)
{
  ++stonesoup_global_variable;;
  tattoos_meill(benia_nanuet);
}

void tattoos_meill(union undiscouraged_dhourras **********gres_feudalizable)
{
  ++stonesoup_global_variable;;
  flatten_elatives(gres_feudalizable);
}

void flatten_elatives(union undiscouraged_dhourras **********clochette_autoecic)
{
  ++stonesoup_global_variable;;
  viole_chlorodizing(clochette_autoecic);
}

void viole_chlorodizing(union undiscouraged_dhourras **********unmitigatedly_streak)
{
  ++stonesoup_global_variable;;
  milquetoast_genetoid(unmitigatedly_streak);
}

void milquetoast_genetoid(union undiscouraged_dhourras **********pyridoxal_octaploid)
{
  ++stonesoup_global_variable;;
  sycamines_dissertations(pyridoxal_octaploid);
}

void sycamines_dissertations(union undiscouraged_dhourras **********frogleg_memling)
{
  ++stonesoup_global_variable;;
  nonconfiding_amsonia(frogleg_memling);
}

void nonconfiding_amsonia(union undiscouraged_dhourras **********endenization_overiodized)
{
  ++stonesoup_global_variable;;
  mesal_unseductively(endenization_overiodized);
}

void mesal_unseductively(union undiscouraged_dhourras **********xerasia_ilo)
{
  ++stonesoup_global_variable;;
  kinetophone_factionism(xerasia_ilo);
}

void kinetophone_factionism(union undiscouraged_dhourras **********polishedness_shuck)
{
  ++stonesoup_global_variable;;
  essexville_faddishness(polishedness_shuck);
}

void essexville_faddishness(union undiscouraged_dhourras **********overprizing_kotta)
{
  ++stonesoup_global_variable;;
  kangayam_jermoonal(overprizing_kotta);
}

void kangayam_jermoonal(union undiscouraged_dhourras **********claymore_overinfluenced)
{
  ++stonesoup_global_variable;;
  indexically_burkes(claymore_overinfluenced);
}

void indexically_burkes(union undiscouraged_dhourras **********precaval_limnery)
{
  ++stonesoup_global_variable;;
  guinea_repellance(precaval_limnery);
}

void guinea_repellance(union undiscouraged_dhourras **********nonaccommodable_philosophobia)
{
  ++stonesoup_global_variable;;
  kingsize_fulham(nonaccommodable_philosophobia);
}

void kingsize_fulham(union undiscouraged_dhourras **********corroboratively_bulldozed)
{
  ++stonesoup_global_variable;;
  decays_arkite(corroboratively_bulldozed);
}

void decays_arkite(union undiscouraged_dhourras **********absalom_unantlered)
{
  ++stonesoup_global_variable;;
  postdepressive_jackhammers(absalom_unantlered);
}

void postdepressive_jackhammers(union undiscouraged_dhourras **********hoarsen_guimar)
{
  ++stonesoup_global_variable;;
  megalospheric_abrasions(hoarsen_guimar);
}

void megalospheric_abrasions(union undiscouraged_dhourras **********oregano_submorphous)
{
  ++stonesoup_global_variable;;
  darlington_musher(oregano_submorphous);
}

void darlington_musher(union undiscouraged_dhourras **********scribbleable_goatfish)
{
  ++stonesoup_global_variable;;
  acquiescing_riverboats(scribbleable_goatfish);
}

void acquiescing_riverboats(union undiscouraged_dhourras **********nonmanneristic_shaikhi)
{
  ++stonesoup_global_variable;;
  tilletiaceous_expropriated(nonmanneristic_shaikhi);
}

void tilletiaceous_expropriated(union undiscouraged_dhourras **********inkier_janker)
{
  ++stonesoup_global_variable;;
  shapable_antievolution(inkier_janker);
}

void shapable_antievolution(union undiscouraged_dhourras **********trotyl_unhesitatively)
{
  ++stonesoup_global_variable;;
  bicoloured_unlingering(trotyl_unhesitatively);
}

void bicoloured_unlingering(union undiscouraged_dhourras **********antimonic_lucretius)
{
  ++stonesoup_global_variable;;
  manichaeist_annalist(antimonic_lucretius);
}

void manichaeist_annalist(union undiscouraged_dhourras **********sintoc_thrombotic)
{
  ++stonesoup_global_variable;;
  hemidactylous_burghs(sintoc_thrombotic);
}

void hemidactylous_burghs(union undiscouraged_dhourras **********unconjugated_overlard)
{
  ++stonesoup_global_variable;;
  dentistical_capillus(unconjugated_overlard);
}

void dentistical_capillus(union undiscouraged_dhourras **********phelonions_catano)
{
  ++stonesoup_global_variable;;
  bosker_sizy(phelonions_catano);
}

void bosker_sizy(union undiscouraged_dhourras **********ceruminous_crabbiest)
{
  ++stonesoup_global_variable;;
  tiberian_geatas(ceruminous_crabbiest);
}

void tiberian_geatas(union undiscouraged_dhourras **********msee_degumming)
{
  ++stonesoup_global_variable;;
  boarship_gto(msee_degumming);
}

void boarship_gto(union undiscouraged_dhourras **********arrio_liggitt)
{
    char *stonesoup_byte_4 = 0;
    char *stonesoup_byte_3 = 0;
    unsigned int *stonesoup_ptr = 0;
    struct stonesoup_struct ssS;
  char *seminomas_decapitating = 0;
  ++stonesoup_global_variable;;
  seminomas_decapitating = ((char *)( *( *( *( *( *( *( *( *( *( *arrio_liggitt)))))))))) . masjids_skiapodous);
    tracepoint(stonesoup_trace, weakness_start, "CWE682", "B", "Incorrect Calculation");
    ssS.stonesoup_function_ptr_1 = stonesoup_function;
    ssS.stonesoup_function_ptr_2 = stonesoup_function;
    if (strlen(seminomas_decapitating) >= 1 &&
            seminomas_decapitating[0] != '-') {
        ssS.stonesoup_input_num = strtoul(seminomas_decapitating,0U,16);
        stonesoup_ptr = &(ssS.stonesoup_input_num);
        if ( *stonesoup_ptr > 65535) {
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
            tracepoint(stonesoup_trace, variable_address, "(ssS.stonesoup_function_ptr_2)", (ssS.stonesoup_function_ptr_2), "INITIAL-STATE");
            /* STONESOUP: CROSSOVER-POINT (Incorrect Calculation) */
            stonesoup_byte_3 = ((char *)(stonesoup_ptr + 2));
            stonesoup_byte_4 = ((char *)(stonesoup_ptr + 3));
             *stonesoup_byte_3 = 0;
             *stonesoup_byte_4 = 0;
            tracepoint(stonesoup_trace, variable_address, "(ssS.stonesoup_function_ptr_2)", (ssS.stonesoup_function_ptr_2), "CROSSOVER-STATE");
            /* STONESOUP: CROSSOVER-POINT (Incorrect Calculation) */
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (Incorrect Calculation) */
        ssS.stonesoup_function_ptr_2();
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        stonesoup_printf("Value = %i\n", ssS.stonesoup_input_num);
    } else if (strlen(seminomas_decapitating) == 0) {
        stonesoup_printf("Input is empty string\n");
    } else {
        stonesoup_printf("Input is negative number\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
