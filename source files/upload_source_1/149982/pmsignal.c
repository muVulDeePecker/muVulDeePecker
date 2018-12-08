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
#include <fcntl.h> 
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
int giuseppe_desulfurization = 0;

struct picolin_reminted 
{
  char *kingsman_rostroantennary;
  double axis_lymphogenous;
  char *ebner_alshain;
  char int_hes;
  int impropriator_thriftbox;
}
;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *morazan_acedias);
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpGCkUgk_ss_testcase/src-rose/src/backend/storage/ipc/pmsignal.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading from sync file.");
}
void waitForChange(char* file, char* sleepFile) {
    int fd;
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpGCkUgk_ss_testcase/src-rose/src/backend/storage/ipc/pmsignal.c", "stonesoup_waitForChange");
    stonesoup_printf("In waitForChange\n");
    strcat(filename, file);
    strcat(filename, ".pid");
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error writing to file.");
            stonesoup_printf("Error writing to file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Wrote .pid file.");
        if (close(fd) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error closing file.");
            stonesoup_printf("Error closing file.");
        }
        stonesoup_readFile(sleepFile);
    }
}
int stonesoup_is_valid(char *path)
{
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpGCkUgk_ss_testcase/src-rose/src/backend/storage/ipc/pmsignal.c", "stonesoup_is_valid");
    if(access(path, F_OK) != -1) {
        tracepoint(stonesoup_trace, trace_point, "Path is accessible");
        stonesoup_printf("Path is accessible\n");
        return 1;
    }
    tracepoint(stonesoup_trace, trace_point, "Path is not accessible");
    stonesoup_printf("Path is not accessible\n");
    return 0;
}
int stonesoup_path_is_relative(char *path) {
    char *chr = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpGCkUgk_ss_testcase/src-rose/src/backend/storage/ipc/pmsignal.c", "stonesoup_path_is_relative");
    chr = strchr(path,'/');
    if (chr == 0) {
        stonesoup_printf("Path is relative\n");
        return 1;
    } else {
        stonesoup_printf("Path is not relative\n");
        return 0;
    }
}
char * stonesoup_get_absolute_path(char * path) {
    char * abs_path = malloc (sizeof(char) * (strlen("/opt/stonesoup/workspace/testData/") * strlen(path) + 1));
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpGCkUgk_ss_testcase/src-rose/src/backend/storage/ipc/pmsignal.c", "stonesoup_get_absolute_path");
    if (abs_path == NULL) {
        tracepoint(stonesoup_trace, trace_error, "Cannot allocate memory for path");
        stonesoup_printf("Cannot allocate memory for path\n");
    } else {
        stonesoup_printf("Creating absolute path\n");
        strcpy(abs_path, "/opt/stonesoup/workspace/testData/");
        tracepoint(stonesoup_trace, variable_buffer, "abs_path", abs_path, "Generated absolute path");
        strcat(abs_path, path);
    }
    return abs_path;
}

Size PMSignalShmemSize()
{
  Size size;
  if (__sync_bool_compare_and_swap(&giuseppe_desulfurization,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpGCkUgk_ss_testcase/src-rose/src/backend/storage/ipc/pmsignal.c","PMSignalShmemSize");
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

void stonesoup_handle_taint(char *morazan_acedias)
{
    int stonesoup_size = 0;
    FILE *stonesoup_file = 0;
    char *stonesoup_buffer = 0;
    char *stonesoup_str = 0;
    char *stonesoup_abs_path = 0;
    char *stonesoup_sleep_file = 0;
  char *moiling_frgs = 0;
  int novanglican_fissura;
  int equitation_broadhead;
  struct picolin_reminted sheartail_janene = {0};
  int **********dampy_polygamian = 0;
  int *********coiffing_biometry = 0;
  int ********indescribably_urbias = 0;
  int *******raasch_sharlene = 0;
  int ******inbreath_unburied = 0;
  int *****meatometer_tonal = 0;
  int ****voidableness_anend = 0;
  int ***goajiro_nattier = 0;
  int **bettongia_nonaspirating = 0;
  int *dynamotor_mastigure = 0;
  int muchfold_cardiocirrhosis;
  struct picolin_reminted enforcer_gothicizing[10] = {0};
  struct picolin_reminted misprision_lungflower;
  ++stonesoup_global_variable;;
  if (morazan_acedias != 0) {;
    misprision_lungflower . kingsman_rostroantennary = ((char *)morazan_acedias);
    muchfold_cardiocirrhosis = 5;
    dynamotor_mastigure = &muchfold_cardiocirrhosis;
    bettongia_nonaspirating = &dynamotor_mastigure;
    goajiro_nattier = &bettongia_nonaspirating;
    voidableness_anend = &goajiro_nattier;
    meatometer_tonal = &voidableness_anend;
    inbreath_unburied = &meatometer_tonal;
    raasch_sharlene = &inbreath_unburied;
    indescribably_urbias = &raasch_sharlene;
    coiffing_biometry = &indescribably_urbias;
    dampy_polygamian = &coiffing_biometry;
    enforcer_gothicizing[ *( *( *( *( *( *( *( *( *( *dampy_polygamian)))))))))] = misprision_lungflower;
    sheartail_janene = enforcer_gothicizing[ *( *( *( *( *( *( *( *( *( *dampy_polygamian)))))))))];
    equitation_broadhead = 5;
    while(1 == 1){
      equitation_broadhead = equitation_broadhead * 2;
      equitation_broadhead = equitation_broadhead + 2;
      if (equitation_broadhead > 1000) {
        break; 
      }
    }
    novanglican_fissura = equitation_broadhead;
    moiling_frgs = ((char *)sheartail_janene . kingsman_rostroantennary);
    tracepoint(stonesoup_trace, weakness_start, "CWE367", "A", "Time of Check Time of Use Race Condition");
    stonesoup_str = malloc(sizeof(char) * (strlen(moiling_frgs) + 1));
    stonesoup_sleep_file = malloc(sizeof(char) * (strlen(moiling_frgs) + 1));
    if (stonesoup_str != NULL && stonesoup_sleep_file != NULL &&
        (sscanf(moiling_frgs, "%s %s",
                stonesoup_sleep_file,
                stonesoup_str) == 2) &&
        (strlen(stonesoup_str) != 0) &&
        (strlen(stonesoup_sleep_file) != 0))
    {
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_sleep_file", stonesoup_sleep_file, "INITIAL-STATE");
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_str", stonesoup_str, "INITIAL-STATE");
        if (stonesoup_path_is_relative(stonesoup_str)) {
            stonesoup_abs_path = stonesoup_get_absolute_path(stonesoup_str);
            if (stonesoup_abs_path != NULL) {
               if (stonesoup_is_valid(stonesoup_abs_path)) {
                  tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
                    /* STONESOUP: CROSSOVER-POINT (Time of Check, Time of Use) */
                    waitForChange(stonesoup_abs_path, stonesoup_sleep_file);
                   tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
                   tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
                    /* STONESOUP: TRIGGER-POINT (Time of Check, Time of Use) */
                    stonesoup_file = fopen(stonesoup_abs_path,"rb");
                    fseek(stonesoup_file,0,2);
                    stonesoup_size = ftell(stonesoup_file);
                    rewind(stonesoup_file);
                    stonesoup_buffer = ((char *)(malloc(sizeof(char ) * (stonesoup_size + 1))));
                    if (stonesoup_buffer != NULL) {
                        fread(stonesoup_buffer,sizeof(char ),stonesoup_size,stonesoup_file);
                        stonesoup_buffer[stonesoup_size] = '\0';
                        stonesoup_printf(stonesoup_buffer);
                        free(stonesoup_buffer);
                    }
                   tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
                    fclose(stonesoup_file);
                }
            }
            free(stonesoup_abs_path);
        }
        free(stonesoup_str);
    } else {
       tracepoint(stonesoup_trace, trace_error, "Error parsing input");
        stonesoup_printf("Error parsing input.\n");
    }
;
    if (sheartail_janene . kingsman_rostroantennary != 0) 
      free(((char *)sheartail_janene . kingsman_rostroantennary));
stonesoup_close_printf_context();
  }
}
