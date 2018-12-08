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
#include <pthread.h> 
static SlruCtlData SubTransCtlData;
#define SubTransCtl  (&SubTransCtlData)
static int ZeroSUBTRANSPage(int pageno);
static bool SubTransPagePrecedes(int page1,int page2);
/*
 * Record the parent of a subtransaction in the subtrans log.
 *
 * In some cases we may need to overwrite an existing value.
 */
int rankine_crojik = 0;
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
void womanfully_tpc(int skye_redraft,char *cytome_uncaptivate);
void roadeo_metalworks(int coprophagy_sapele,char *marshberries_diacrisis);
struct stonesoup_data {
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
pthread_mutex_t stonesoup_mutex_0, stonesoup_mutex_1;
pthread_t stonesoup_t0, stonesoup_t1;
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpJ1T2fU_ss_testcase/src-rose/src/backend/access/transam/subtrans.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void *stonesoup_replace (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int *qsort_arr;
    int i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpJ1T2fU_ss_testcase/src-rose/src/backend/access/transam/subtrans.c", "stonesoup_replace");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    stonesoup_printf("replace: entering function\n");
    /* slow things down to make correct thing happen in good cases */
    qsort_arr = malloc(sizeof(int)*stonesoupData->qsize);
    if (qsort_arr != NULL) {
        for (i = 0; i < stonesoupData->qsize; i++) {
            qsort_arr[i] = stonesoupData->qsize - i;
        }
        qsort(qsort_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
        free (qsort_arr);
        qsort_arr = NULL;
    }
    stonesoup_readFile(stonesoupData->file1);
    stonesoup_printf("replace: Attempting to grab lock 0\n");
    pthread_mutex_lock(&stonesoup_mutex_0);
    stonesoup_printf("replace: Grabbed lock 0\n");
    stonesoup_printf("replace: Attempting to grab lock 1\n");
    pthread_mutex_lock(&stonesoup_mutex_1); /* DEADLOCK */
    stonesoup_printf("replace: Grabbed lock 1\n");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        if (stonesoupData->data[i] == '_') {
            stonesoupData->data[i] = '-';
        }
        i++;
    }
    stonesoup_printf("replace: Releasing lock 1\n");
    pthread_mutex_unlock(&stonesoup_mutex_1);
    stonesoup_printf("replace: Releasing lock 0\n");
    pthread_mutex_unlock(&stonesoup_mutex_0);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    return NULL;
}
void *stonesoup_toCap (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpJ1T2fU_ss_testcase/src-rose/src/backend/access/transam/subtrans.c", "stonesoup_toCap");
    stonesoup_printf("toCap:   Entering function\n");
    stonesoup_printf("toCap:   Attempting to grab lock 1\n");
    pthread_mutex_lock(&stonesoup_mutex_1);
    stonesoup_printf("toCap:   Grabbed lock 1\n");
    stonesoup_readFile(stonesoupData->file2);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (deadlock) */
    stonesoup_printf("toCap:   Attempting to grab lock 0\n");
    pthread_mutex_lock(&stonesoup_mutex_0); /* DEADLOCK */
    stonesoup_printf("toCap:   Grabbed lock 0\n");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        if (stonesoupData->data[i] > 'a' && stonesoupData->data[i] < 'z') {
            stonesoupData->data[i] -= 'a' - 'A';
        }
        i++;
    }
    stonesoup_printf("toCap:   Releasing lock 0\n");
    pthread_mutex_unlock(&stonesoup_mutex_0);
    stonesoup_printf("toCap:   Releasing lock 1\n");
    pthread_mutex_unlock(&stonesoup_mutex_1);
    return NULL;
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
  int arcose_tenography = 7;
  char *spiritleaf_piqure = 0;
  int **hemolysin_supersubtilized = 0;
  int *eurythermous_fissipeda = 0;
  int jackeroo_locofocos;
  char *antidecalogue_ethysulphuric[10] = {0};
  char *ismdom_piteous;
  int startPage;
  int endPage;
  if (__sync_bool_compare_and_swap(&rankine_crojik,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpJ1T2fU_ss_testcase/src-rose/src/backend/access/transam/subtrans.c","StartupSUBTRANS");
      stonesoup_setup_printf_context();
      ismdom_piteous = getenv("OBLIQUE_WORKPLACE");
      if (ismdom_piteous != 0) {;
        jackeroo_locofocos = 5;
        eurythermous_fissipeda = &jackeroo_locofocos;
        hemolysin_supersubtilized = &eurythermous_fissipeda;
        antidecalogue_ethysulphuric[ *( *hemolysin_supersubtilized)] = ismdom_piteous;
        spiritleaf_piqure = antidecalogue_ethysulphuric[ *( *hemolysin_supersubtilized)];
        womanfully_tpc(arcose_tenography,spiritleaf_piqure);
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

void womanfully_tpc(int skye_redraft,char *cytome_uncaptivate)
{
    int stonesoup_hasUnderscores = 0;
    int stonesoup_i = 0;
    struct stonesoup_data* stonesoupData;
  char *touret_reaffirmance = 0;
  ++stonesoup_global_variable;
  skye_redraft--;
  if (skye_redraft > 0) {
    roadeo_metalworks(skye_redraft,cytome_uncaptivate);
    return ;
  }
  touret_reaffirmance = ((char *)cytome_uncaptivate);
    tracepoint(stonesoup_trace, weakness_start, "CWE833", "A", "Deadlock");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(touret_reaffirmance) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(touret_reaffirmance) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(touret_reaffirmance) + 1));
        if (stonesoupData->data) {
            if ((sscanf(touret_reaffirmance, "%d %s %s %s",
                      &(stonesoupData->qsize),
                        stonesoupData->file1,
                        stonesoupData->file2,
                        stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0) &&
                (strlen(stonesoupData->file2) != 0))
            {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
                pthread_mutex_init(&stonesoup_mutex_0, NULL);
                pthread_mutex_init(&stonesoup_mutex_1, NULL);
                while(stonesoupData->data[stonesoup_i] != '\0') { /* if the input contains underscores */
                    if (stonesoupData->data[stonesoup_i++] == '_') { /*   we call the deadlocking function */
                        stonesoup_hasUnderscores = 1;
                    }
                }
                tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
                if (pthread_create(&stonesoup_t0, NULL, stonesoup_toCap, stonesoupData) != 0) {
                    stonesoup_printf("Thread 0 failed to spawn.");
                }
                if (stonesoup_hasUnderscores == 1) {
                    /* STONESOUP: CROSSOVER-POINT (deadlock) */
                    if (pthread_create(&stonesoup_t1, NULL, stonesoup_replace, stonesoupData) != 0) {
                        stonesoup_printf("Thread 1 failed to spawn.");
                    }
                }
                pthread_join(stonesoup_t0, NULL);
                if (stonesoup_hasUnderscores == 1) {
                    pthread_join(stonesoup_t1, NULL);
                }
                tracepoint(stonesoup_trace, trace_point, "Threads joined.");
                pthread_mutex_destroy(&stonesoup_mutex_0);
                pthread_mutex_destroy(&stonesoup_mutex_1);
            } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data");
                stonesoup_printf("Error parsing data\n");
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}

void roadeo_metalworks(int coprophagy_sapele,char *marshberries_diacrisis)
{
  ++stonesoup_global_variable;
  womanfully_tpc(coprophagy_sapele,marshberries_diacrisis);
}
