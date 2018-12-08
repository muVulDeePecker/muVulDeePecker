/*-------------------------------------------------------------------------
 *
 * pmsignal.c
 *	  routines for signaling the postmaster from its child processes
 *
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/storage/ipc/pmsignal.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include <signal.h>
#include <unistd.h>
#include "miscadmin.h"
#include "postmaster/postmaster.h"
#include "replication/walsender.h"
#include "storage/pmsignal.h"
#include "storage/shmem.h"
/*
 * The postmaster is signaled by its children by sending SIGUSR1.  The
 * specific reason is communicated via flags in shared memory.	We keep
 * a boolean flag for each possible "reason", so that different reasons
 * can be signaled by different backends at the same time.	(However,
 * if the same reason is signaled more than once simultaneously, the
 * postmaster will observe it only once.)
 *
 * The flags are actually declared as "volatile sig_atomic_t" for maximum
 * portability.  This should ensure that loads and stores of the flag
 * values are atomic, allowing us to dispense with any explicit locking.
 *
 * In addition to the per-reason flags, we store a set of per-child-process
 * flags that are currently used only for detecting whether a backend has
 * exited without performing proper shutdown.  The per-child-process flags
 * have three possible states: UNUSED, ASSIGNED, ACTIVE.  An UNUSED slot is
 * available for assignment.  An ASSIGNED slot is associated with a postmaster
 * child process, but either the process has not touched shared memory yet,
 * or it has successfully cleaned up after itself.	A ACTIVE slot means the
 * process is actively using shared memory.  The slots are assigned to
 * child processes at random, and postmaster.c is responsible for tracking
 * which one goes with which PID.
 *
 * Actually there is a fourth state, WALSENDER.  This is just like ACTIVE,
 * but carries the extra information that the child is a WAL sender.
 * WAL senders too start in ACTIVE state, but switch to WALSENDER once they
 * start streaming the WAL (and they never go back to ACTIVE after that).
 */
#define PM_CHILD_UNUSED		0	/* these values must fit in sig_atomic_t */
#define PM_CHILD_ASSIGNED	1
#define PM_CHILD_ACTIVE		2
#define PM_CHILD_WALSENDER	3
/* "typedef struct PMSignalData PMSignalData" appears in pmsignal.h */
#include <mongoose.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <sys/stat.h> 

struct PMSignalData 
{
/* per-reason flags */
  sig_atomic_t PMSignalFlags[NUM_PMSIGNALS];
/* per-child-process flags */
/* # of entries in PMChildFlags[] */
  int num_child_flags;
/* next slot to try to assign */
  int next_child_flag;
/* VARIABLE LENGTH ARRAY */
  sig_atomic_t PMChildFlags[1];
}
;
static volatile PMSignalData *PMSignalState = ((void *)0);
/*
 * PMSignalShmemSize
 *		Compute space needed for pmsignal.c's shared memory
 */
int kaf_arguta = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *overinfluential_begut);
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

Size PMSignalShmemSize()
{
  Size size;
  if (__sync_bool_compare_and_swap(&kaf_arguta,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpczDudF_ss_testcase/src-rose/src/backend/storage/ipc/pmsignal.c","PMSignalShmemSize");
      stonesoup_read_taint();
    }
  }
  size = ((size_t )(&((PMSignalData *)0) -> PMChildFlags));
  size = add_size(size,mul_size((MaxLivePostmasterChildren()),sizeof(sig_atomic_t )));
  return size;
}
/*
 * PMSignalShmemInit - initialize during shared-memory creation
 */

void PMSignalShmemInit()
{
  bool found;
  PMSignalState = ((PMSignalData *)(ShmemInitStruct("PMSignalState",PMSignalShmemSize(),&found)));
  if (!found) {
    do {
      void *_vstart = (void *)PMSignalState;
      int _val = 0;
      Size _len = PMSignalShmemSize();
      if ((((intptr_t )_vstart) & sizeof(long ) - 1) == 0 && (_len & sizeof(long ) - 1) == 0 && _val == 0 && _len <= 1024 && 1024 != 0) {
        long *_start = (long *)_vstart;
        long *_stop = (long *)(((char *)_start) + _len);
        while(_start < _stop)
           *(_start++) = 0;
      }
      else {
        memset(_vstart,_val,_len);
      }
    }while (0);
    PMSignalState -> num_child_flags = MaxLivePostmasterChildren();
  }
}
/*
 * SendPostmasterSignal - signal the postmaster from a child process
 */

void SendPostmasterSignal(PMSignalReason reason)
{
/* If called in a standalone backend, do nothing */
  if (!IsUnderPostmaster) {
    return ;
  }
/* Atomically set the proper flag */
  PMSignalState -> PMSignalFlags[reason] = ((bool )1);
/* Send signal to postmaster */
  kill(PostmasterPid,10);
}
/*
 * CheckPostmasterSignal - check to see if a particular reason has been
 * signaled, and clear the signal flag.  Should be called by postmaster
 * after receiving SIGUSR1.
 */

bool CheckPostmasterSignal(PMSignalReason reason)
{
/* Careful here --- don't clear flag if we haven't seen it set */
  if (PMSignalState -> PMSignalFlags[reason]) {
    PMSignalState -> PMSignalFlags[reason] = ((bool )0);
    return (bool )1;
  }
  return (bool )0;
}
/*
 * AssignPostmasterChildSlot - select an unused slot for a new postmaster
 * child process, and set its state to ASSIGNED.  Returns a slot number
 * (one to N).
 *
 * Only the postmaster is allowed to execute this routine, so we need no
 * special locking.
 */

int AssignPostmasterChildSlot()
{
  int slot = PMSignalState -> next_child_flag;
  int n;
/*
	 * Scan for a free slot.  We track the last slot assigned so as not to
	 * waste time repeatedly rescanning low-numbered slots.
	 */
  for (n = PMSignalState -> num_child_flags; n > 0; n--) {
    if (--slot < 0) {
      slot = PMSignalState -> num_child_flags - 1;
    }
    if (PMSignalState -> PMChildFlags[slot] == 0) {
      PMSignalState -> PMChildFlags[slot] = 1;
      PMSignalState -> next_child_flag = slot;
      return slot + 1;
    }
  }
/* Out of slots ... should never happen, else postmaster.c messed up */
  (elog_start("pmsignal.c",173,__func__) , elog_finish(21,"no free slots in PMChildFlags array"));
/* keep compiler quiet */
  return 0;
}
/*
 * ReleasePostmasterChildSlot - release a slot after death of a postmaster
 * child process.  This must be called in the postmaster process.
 *
 * Returns true if the slot had been in ASSIGNED state (the expected case),
 * false otherwise (implying that the child failed to clean itself up).
 */

bool ReleasePostmasterChildSlot(int slot)
{
  bool result;
  ;
  slot--;
/*
	 * Note: the slot state might already be unused, because the logic in
	 * postmaster.c is such that this might get called twice when a child
	 * crashes.  So we don't try to Assert anything about the state.
	 */
  result = (PMSignalState -> PMChildFlags[slot] == 1);
  PMSignalState -> PMChildFlags[slot] = 0;
  return result;
}
/*
 * IsPostmasterChildWalSender - check if given slot is in use by a
 * walsender process.
 */

bool IsPostmasterChildWalSender(int slot)
{
  ;
  slot--;
  if (PMSignalState -> PMChildFlags[slot] == 3) {
    return (bool )1;
  }
  else {
    return (bool )0;
  }
}
/*
 * MarkPostmasterChildActive - mark a postmaster child as about to begin
 * actively using shared memory.  This is called in the child process.
 */

void MarkPostmasterChildActive()
{
  int slot = MyPMChildSlot;
  ;
  slot--;
  ;
  PMSignalState -> PMChildFlags[slot] = 2;
}
/*
 * MarkPostmasterChildWalSender - mark a postmaster child as a WAL sender
 * process.  This is called in the child process, sometime after marking the
 * child as active.
 */

void MarkPostmasterChildWalSender()
{
  int slot = MyPMChildSlot;
  ;
  ;
  slot--;
  ;
  PMSignalState -> PMChildFlags[slot] = 3;
}
/*
 * MarkPostmasterChildInactive - mark a postmaster child as done using
 * shared memory.  This is called in the child process.
 */

void MarkPostmasterChildInactive()
{
  int slot = MyPMChildSlot;
  ;
  slot--;
  ;
  PMSignalState -> PMChildFlags[slot] = 1;
}
/*
 * PostmasterIsAlive - check whether postmaster process is still alive
 */

bool PostmasterIsAlive()
{
#ifndef WIN32
  char c;
  ssize_t rc;
  rc = read(postmaster_alive_fds[0],(&c),1);
  if (rc < 0) {
    if ( *__errno_location() == 11 ||  *__errno_location() == 11) {
      return (bool )1;
    }
    else {
      (elog_start("pmsignal.c",284,__func__) , elog_finish(21,"read on postmaster death monitoring pipe failed: %m"));
    }
  }
  else {
    if (rc > 0) {
      (elog_start("pmsignal.c",287,__func__) , elog_finish(21,"unexpected data in postmaster death monitoring pipe"));
    }
  }
  return (bool )0;
#else							/* WIN32 */
#endif   /* WIN32 */
}

void stonesoup_handle_taint(char *overinfluential_begut)
{
 int stonesoup_ss_i = 0;
  char *provincialize_reg = 0;
  char ***************************************************superabound_nondigestibly = 0;
  char **************************************************killing_vialogue = 0;
  char *************************************************headspring_coburgess = 0;
  char ************************************************wheaties_continuedly = 0;
  char ***********************************************acecaffine_ballocks = 0;
  char **********************************************promotive_rockeries = 0;
  char *********************************************anat_fuseless = 0;
  char ********************************************metewand_fluttered = 0;
  char *******************************************unworkmanlike_pulitzer = 0;
  char ******************************************spelunked_accustomedly = 0;
  char *****************************************pliotron_darg = 0;
  char ****************************************nonemphatical_definable = 0;
  char ***************************************noncitizens_syndesmon = 0;
  char **************************************tetartohedral_revibration = 0;
  char *************************************unplainly_incorporator = 0;
  char ************************************cheribon_brat = 0;
  char ***********************************psittaciformes_tachistoscopic = 0;
  char **********************************velometer_avenant = 0;
  char *********************************kawai_vassalism = 0;
  char ********************************intendingly_desirabilities = 0;
  char *******************************micawberism_inwrapt = 0;
  char ******************************calloused_depucel = 0;
  char *****************************submeter_cheesemongerly = 0;
  char ****************************ornas_grottoes = 0;
  char ***************************hiems_rainbowy = 0;
  char **************************reissuing_necia = 0;
  char *************************frequentation_marsileaceous = 0;
  char ************************valinch_anagnostes = 0;
  char ***********************testamentarily_freeman = 0;
  char **********************louch_bentonville = 0;
  char *********************coadjuvant_undreamy = 0;
  char ********************ahong_closemouthed = 0;
  char *******************rubbler_eleometer = 0;
  char ******************monotremous_unstoical = 0;
  char *****************aao_eucairite = 0;
  char ****************tentmaker_strategies = 0;
  char ***************tenorino_skippy = 0;
  char **************bespeaking_northern = 0;
  char *************scampish_photuria = 0;
  char ************nader_belayer = 0;
  char ***********recuperative_rahm = 0;
  char **********cubocube_angle = 0;
  char *********monologues_chippewas = 0;
  char ********embolium_advocates = 0;
  char *******disconform_postarthritic = 0;
  char ******zeidae_imposing = 0;
  char *****subtlest_lallands = 0;
  char ****greenleek_stravinsky = 0;
  char ***nabcheat_unremediable = 0;
  char **harkener_hede = 0;
  char *difluoride_dragoons = 0;
  ++stonesoup_global_variable;;
  if (overinfluential_begut != 0) {;
    harkener_hede = &overinfluential_begut;
    nabcheat_unremediable = &harkener_hede;
    greenleek_stravinsky = &nabcheat_unremediable;
    subtlest_lallands = &greenleek_stravinsky;
    zeidae_imposing = &subtlest_lallands;
    disconform_postarthritic = &zeidae_imposing;
    embolium_advocates = &disconform_postarthritic;
    monologues_chippewas = &embolium_advocates;
    cubocube_angle = &monologues_chippewas;
    recuperative_rahm = &cubocube_angle;
    nader_belayer = &recuperative_rahm;
    scampish_photuria = &nader_belayer;
    bespeaking_northern = &scampish_photuria;
    tenorino_skippy = &bespeaking_northern;
    tentmaker_strategies = &tenorino_skippy;
    aao_eucairite = &tentmaker_strategies;
    monotremous_unstoical = &aao_eucairite;
    rubbler_eleometer = &monotremous_unstoical;
    ahong_closemouthed = &rubbler_eleometer;
    coadjuvant_undreamy = &ahong_closemouthed;
    louch_bentonville = &coadjuvant_undreamy;
    testamentarily_freeman = &louch_bentonville;
    valinch_anagnostes = &testamentarily_freeman;
    frequentation_marsileaceous = &valinch_anagnostes;
    reissuing_necia = &frequentation_marsileaceous;
    hiems_rainbowy = &reissuing_necia;
    ornas_grottoes = &hiems_rainbowy;
    submeter_cheesemongerly = &ornas_grottoes;
    calloused_depucel = &submeter_cheesemongerly;
    micawberism_inwrapt = &calloused_depucel;
    intendingly_desirabilities = &micawberism_inwrapt;
    kawai_vassalism = &intendingly_desirabilities;
    velometer_avenant = &kawai_vassalism;
    psittaciformes_tachistoscopic = &velometer_avenant;
    cheribon_brat = &psittaciformes_tachistoscopic;
    unplainly_incorporator = &cheribon_brat;
    tetartohedral_revibration = &unplainly_incorporator;
    noncitizens_syndesmon = &tetartohedral_revibration;
    nonemphatical_definable = &noncitizens_syndesmon;
    pliotron_darg = &nonemphatical_definable;
    spelunked_accustomedly = &pliotron_darg;
    unworkmanlike_pulitzer = &spelunked_accustomedly;
    metewand_fluttered = &unworkmanlike_pulitzer;
    anat_fuseless = &metewand_fluttered;
    promotive_rockeries = &anat_fuseless;
    acecaffine_ballocks = &promotive_rockeries;
    wheaties_continuedly = &acecaffine_ballocks;
    headspring_coburgess = &wheaties_continuedly;
    killing_vialogue = &headspring_coburgess;
    superabound_nondigestibly = &killing_vialogue;
    provincialize_reg = ((char *)( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *superabound_nondigestibly)))))))))))))))))))))))))))))))))))))))))))))))))));
 tracepoint(stonesoup_trace, weakness_start, "CWE835", "A", "Loop with Unreachable Exit Condition ('Infinite Loop')");
    stonesoup_printf("checking input\n");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", provincialize_reg, "TRIGGER-STATE");
 while(stonesoup_ss_i < strlen(provincialize_reg)){
  /* STONESOUP: CROSSOVER-POINT (Infinite Loop) */
        if (provincialize_reg[stonesoup_ss_i] >= 48) {
   /* STONESOUP: TRIGGER-POINT (Infinite Loop: Unable to reach exit condition) */
   ++stonesoup_ss_i;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
   stonesoup_printf("finished evaluating\n");
    tracepoint(stonesoup_trace, weakness_end);
;
    if ( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *superabound_nondigestibly))))))))))))))))))))))))))))))))))))))))))))))))) != 0) 
      free(((char *)( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *superabound_nondigestibly))))))))))))))))))))))))))))))))))))))))))))))))))));
stonesoup_close_printf_context();
  }
}
