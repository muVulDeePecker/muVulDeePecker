/* crypto/bio/bss_file.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/*
 * 03-Dec-1997	rdenny@dc3.com  Fix bug preventing use of stdin/stdout
 *		with binary data (e.g. asn1parse -inform DER < xxx) under
 *		Windows
 */
#ifndef HEADER_BSS_FILE_C
#define HEADER_BSS_FILE_C
#if defined(__linux) || defined(__sun) || defined(__hpux)
/* Following definition aliases fopen to fopen64 on above mentioned
 * platforms. This makes it possible to open and sequentially access
 * files larger than 2GB from 32-bit application. It does not allow to
 * traverse them beyond 2GB with fseek/ftell, but on the other hand *no*
 * 32-bit platform permits that, not with fseek/ftell. Not to mention
 * that breaking 2GB limit for seeking would require surgery to *our*
 * API. But sequential access suffices for practical cases when you
 * can run into large files, such as fingerprinting, so we can let API
 * alone. For reference, the list of 32-bit platforms which allow for
 * sequential access of large files without extra "magic" comprise *BSD,
 * Darwin, IRIX...
 */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#endif
#include <stdio.h>
#include <errno.h>
#include "cryptlib.h"
#include "bio_lcl.h"
#include <openssl/err.h>
#if defined(OPENSSL_SYS_NETWARE) && defined(NETWARE_CLIB)
#include <nwfileio.h>
#endif
#if !defined(OPENSSL_NO_STDIO)
#include <sys/stat.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
static int file_write(BIO *b,const char *in,int inl);
static int file_read(BIO *b,char *out,int outl);
static int file_puts(BIO *bp,const char *str);
static int file_gets(BIO *bp,char *buf,int size);
static long file_ctrl(BIO *b,int cmd,long num,void *ptr);
static int file_new(BIO *bi);
static int file_free(BIO *a);
static BIO_METHOD methods_filep = {(2 | 0x0400), ("FILE pointer"), (file_write), (file_read), (file_puts), (file_gets), (file_ctrl), (file_new), (file_free), (((void *)0))};
int preforgive_dodecaphony = 0;
int stonesoup_global_variable;

struct ancyloceras_uranoplastic 
{
  char *puirness_nonfragilely;
  double snooled_adventurer;
  char *ophthalmologist_stayed;
  char swordslipper_crotaloid;
  int ammonoids_unempirically;
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
void newsstands_zingari(struct ancyloceras_uranoplastic *communalisation_zacatecas);
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpyxdj5f_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpyxdj5f_ss_testcase/src-rose/crypto/bio/bss_file.c", "Finished reading sync file.");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpyxdj5f_ss_testcase/src-rose/crypto/bio/bss_file.c", "get_instance");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpyxdj5f_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_print_data");
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpyxdj5f_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_calc_data");
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

BIO *BIO_new_file(const char *filename,const char *mode)
{
  BIO *ret;
  FILE *file = ((void *)0);
#if defined(_WIN32) && defined(CP_UTF8)
/*
	 * Basically there are three cases to cover: a) filename is
	 * pure ASCII string; b) actual UTF-8 encoded string and
	 * c) locale-ized string, i.e. one containing 8-bit
	 * characters that are meaningful in current system locale.
	 * If filename is pure ASCII or real UTF-8 encoded string,
	 * MultiByteToWideChar succeeds and _wfopen works. If
	 * filename is locale-ized string, chances are that
	 * MultiByteToWideChar fails reporting
	 * ERROR_NO_UNICODE_TRANSLATION, in which case we fall
	 * back to fopen...
	 */
/* UTF-8 decode succeeded, but no file, filename
			 * could still have been locale-ized... */
#else
  file = fopen(filename,mode);
#endif
  if (file == ((void *)0)) {
    ERR_put_error(2,1, *__errno_location(),"bss_file.c",169);
    ERR_add_error_data(5,"fopen('",filename,"','",mode,"')");
    if ( *__errno_location() == 2) {
      ERR_put_error(32,109,128,"bss_file.c",172);
    }
    else {
      ERR_put_error(32,109,2,"bss_file.c",174);
    }
    return ((void *)0);
  }
  if ((ret = BIO_new(BIO_s_file())) == ((void *)0)) {
    fclose(file);
    return ((void *)0);
  }
/* we did fopen -> we disengage UPLINK */
  BIO_clear_flags(ret,0);
  BIO_ctrl(ret,106,0x01,((char *)file));
  return ret;
}

BIO *BIO_new_fp(FILE *stream,int close_flag)
{
  BIO *ret;
  if ((ret = BIO_new(BIO_s_file())) == ((void *)0)) {
    return ((void *)0);
  }
/* redundant, left for documentation puposes */
  BIO_set_flags(ret,0);
  BIO_ctrl(ret,106,close_flag,((char *)stream));
  return ret;
}

BIO_METHOD *BIO_s_file()
{
  return &methods_filep;
}

static int file_new(BIO *bi)
{
  bi -> init = 0;
  bi -> num = 0;
  bi -> ptr = ((void *)0);
/* default to UPLINK */
  bi -> flags = 0;
  return 1;
}

static int file_free(BIO *a)
{
  if (a == ((void *)0)) {
    return 0;
  }
  if (a -> shutdown) {
    if (a -> init && a -> ptr != ((void *)0)) {
      if (a -> flags & 0) {
        fclose((a -> ptr));
      }
      else {
        fclose((a -> ptr));
      }
      a -> ptr = ((void *)0);
      a -> flags = 0;
    }
    a -> init = 0;
  }
  return 1;
}

static int file_read(BIO *b,char *out,int outl)
{
  int ret = 0;
  if (b -> init && out != ((void *)0)) {
    if (b -> flags & 0) {
      ret = (fread(out,1,((int )outl),(b -> ptr)));
    }
    else {
      ret = (fread(out,1,((int )outl),((FILE *)(b -> ptr))));
    }
    if (ret == 0 && b -> flags & 0?ferror(((FILE *)(b -> ptr))) : ferror(((FILE *)(b -> ptr)))) {
      ERR_put_error(2,11, *__errno_location(),"bss_file.c",245);
      ERR_put_error(32,130,2,"bss_file.c",246);
      ret = - 1;
    }
  }
  return ret;
}

static int file_write(BIO *b,const char *in,int inl)
{
  int ret = 0;
  if (b -> init && in != ((void *)0)) {
    if (b -> flags & 0) {
      ret = (fwrite(in,((int )inl),1,(b -> ptr)));
    }
    else {
      ret = (fwrite(in,((int )inl),1,((FILE *)(b -> ptr))));
    }
    if (ret) {
      ret = inl;
    }
/* ret=fwrite(in,1,(int)inl,(FILE *)b->ptr); */
/* according to Tim Hudson <tjh@cryptsoft.com>, the commented
		 * out version above can cause 'inl' write calls under
		 * some stupid stdio implementations (VMS) */
  }
  return ret;
}
#define NEURILEMMATOUS_NONPERFORMING(x) newsstands_zingari((struct ancyloceras_uranoplastic *) x)

static long file_ctrl(BIO *b,int cmd,long num,void *ptr)
{
  struct ancyloceras_uranoplastic *guytrash_flagler = 0;
  struct ancyloceras_uranoplastic anemony_homosassa = {0};
  struct ancyloceras_uranoplastic americanization_streetway;
  int fana_winther = 91;
  char *oustiti_bicoloured;
  long ret = 1;
  FILE *fp = (FILE *)(b -> ptr);
  FILE **fpp;
  char p[4];
  if (__sync_bool_compare_and_swap(&preforgive_dodecaphony,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpyxdj5f_ss_testcase/src-rose/crypto/bio/bss_file.c","file_ctrl");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&oustiti_bicoloured,"9702",fana_winther);
      if (oustiti_bicoloured != 0) {;
        americanization_streetway . puirness_nonfragilely = ((char *)oustiti_bicoloured);
        guytrash_flagler = &americanization_streetway;
	NEURILEMMATOUS_NONPERFORMING(guytrash_flagler);
      }
    }
  }
  switch(cmd){
    case 128:
{
    }
    case 1:
{
      if (b -> flags & 0) {
        ret = ((long )(fseek((b -> ptr),num,0)));
      }
      else {
        ret = ((long )(fseek(fp,num,0)));
      }
      break; 
    }
    case 2:
{
      if (b -> flags & 0) {
        ret = ((long )(feof(fp)));
      }
      else {
        ret = ((long )(feof(fp)));
      }
      break; 
    }
    case 133:
{
    }
    case 3:
{
      if (b -> flags & 0) {
        ret = ftell((b -> ptr));
      }
      else {
        ret = ftell(fp);
      }
      break; 
    }
    case 106:
{
      file_free(b);
      b -> shutdown = ((int )num) & 0x01;
      b -> ptr = ptr;
      b -> init = 1;
#if BIO_FLAGS_UPLINK!=0
#if defined(__MINGW32__) && defined(__MSVCRT__) && !defined(_IOB_ENTRIES)
#define _IOB_ENTRIES 20
#endif
#if defined(_IOB_ENTRIES)
/* Safety net to catch purely internal BIO_set_fp calls */
#endif
#endif
#ifdef UP_fsetmod
#endif
{
#if defined(OPENSSL_SYS_WINDOWS)
#elif defined(OPENSSL_SYS_NETWARE) && defined(NETWARE_CLIB)
/* Under CLib there are differences in file modes */
#elif defined(OPENSSL_SYS_MSDOS)
/* Set correct text/binary mode */
/* Dangerous to set stdin/stdout to raw (unless redirected) */
#elif defined(OPENSSL_SYS_OS2) || defined(OPENSSL_SYS_WIN32_CYGWIN)
#endif
      }
      break; 
    }
    case 108:
{
      file_free(b);
      b -> shutdown = ((int )num) & 0x01;
      if (num & 0x08) {
        if (num & 0x02) {
          BUF_strlcpy(p,"a+",sizeof(p));
        }
        else {
          BUF_strlcpy(p,"a",sizeof(p));
        }
      }
      else {
        if (num & 0x02 && num & 0x04) {
          BUF_strlcpy(p,"r+",sizeof(p));
        }
        else {
          if (num & 0x04) {
            BUF_strlcpy(p,"w",sizeof(p));
          }
          else {
            if (num & 0x02) {
              BUF_strlcpy(p,"r",sizeof(p));
            }
            else {
              ERR_put_error(32,116,101,"bss_file.c",379);
              ret = 0;
              break; 
            }
          }
        }
      }
#if defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_OS2) || defined(OPENSSL_SYS_WIN32_CYGWIN)
#endif
#if defined(OPENSSL_SYS_NETWARE)
#endif
      fp = fopen(ptr,p);
      if (fp == ((void *)0)) {
        ERR_put_error(2,1, *__errno_location(),"bss_file.c",398);
        ERR_add_error_data(5,"fopen('",ptr,"','",p,"')");
        ERR_put_error(32,116,2,"bss_file.c",400);
        ret = 0;
        break; 
      }
      b -> ptr = fp;
      b -> init = 1;
/* we did fopen -> we disengage UPLINK */
      BIO_clear_flags(b,0);
      break; 
    }
    case 107:
{
/* the ptr parameter is actually a FILE ** in this case. */
      if (ptr != ((void *)0)) {
        fpp = ((FILE **)ptr);
         *fpp = ((FILE *)(b -> ptr));
      }
      break; 
    }
    case 8:
{
      ret = ((long )(b -> shutdown));
      break; 
    }
    case 9:
{
      b -> shutdown = ((int )num);
      break; 
    }
    case 11:
{
      if (b -> flags & 0) {
        fflush((b -> ptr));
      }
      else {
        fflush(((FILE *)(b -> ptr)));
      }
      break; 
    }
    case 12:
{
      ret = 1;
      break; 
    }
    case 13:
{
    }
    case 10:
{
    }
    case 6:
{
    }
    case 7:
{
    }
    default:
{
      ret = 0;
      break; 
    }
  }
  return ret;
}

static int file_gets(BIO *bp,char *buf,int size)
{
  int ret = 0;
  buf[0] = '\0';
  if (bp -> flags & 0) {
    if (!fgets(buf,size,(bp -> ptr))) {
      goto err;
    }
  }
  else {
    if (!fgets(buf,size,((FILE *)(bp -> ptr)))) {
      goto err;
    }
  }
  if (buf[0] != '\0') {
    ret = (strlen(buf));
  }
  err:
  return ret;
}

static int file_puts(BIO *bp,const char *str)
{
  int n;
  int ret;
  n = (strlen(str));
  ret = file_write(bp,str,n);
  return ret;
}

void newsstands_zingari(struct ancyloceras_uranoplastic *communalisation_zacatecas)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data* stonesoupData;
  char *coalers_sapples = 0;
  ++stonesoup_global_variable;;
  coalers_sapples = ((char *)( *communalisation_zacatecas) . puirness_nonfragilely);
    tracepoint(stonesoup_trace, weakness_start, "CWE543", "A", "Use of a Singleton Pattern Without Synchronization in a Multithreaded Context");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(coalers_sapples) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(coalers_sapples) + 1));
        if ((sscanf(coalers_sapples, "%d %s %s %d",
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
  if (( *communalisation_zacatecas) . puirness_nonfragilely != 0) 
    free(((char *)( *communalisation_zacatecas) . puirness_nonfragilely));
stonesoup_close_printf_context();
}
#endif /* OPENSSL_NO_STDIO */
#endif /* HEADER_BSS_FILE_C */
