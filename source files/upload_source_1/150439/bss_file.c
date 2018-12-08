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
int pommeller_cataphracted = 0;
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
void *kingu_lionizable(void *seisable_interrupter);
void peckville_thiocarbanilide(int sprattling_ballocks,void *edmondson_nonelectrolyte);
struct stonesoup_data {
    int inc_amount;
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
int stonesoup_comp (const void * a, const void * b) {
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
int stonesoup_pmoc (const void * a, const void * b) {
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpEYoWih_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void *calcIncamount(void *data) {
    struct stonesoup_data *dataStruct = (struct stonesoup_data*)data;
    stonesoup_printf("In calcInamount\n");
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpEYoWih_ss_testcase/src-rose/crypto/bio/bss_file.c", "calcIncamount");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    /* STONESOUP: CROSSOVER-POINT (missing syncronization) */
    dataStruct->inc_amount = dataStruct->data[0] - 'A'; /* oops...um... */
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "CROSSOVER-STATE");
    stonesoup_readFile(dataStruct->file2);
    if (dataStruct->inc_amount < 0) { /* let's just clean up and */
        dataStruct->inc_amount *= -1; /*  pretend that never happened */
    }
    else if (dataStruct->inc_amount == 0) { /*  shhhh */
        dataStruct->inc_amount += 1;
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "FINAL-STATE");
    return NULL;
}
void *toPound(void *data) {
    int stonesoup_i;
    struct stonesoup_data *dataStruct = (struct stonesoup_data*)data;
    int *stonesoup_arr = NULL;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpEYoWih_ss_testcase/src-rose/crypto/bio/bss_file.c", "toPound");
    stonesoup_printf("In toPound\n");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int) * dataStruct->qsize);
    for (stonesoup_i = 0; stonesoup_i < dataStruct->qsize; stonesoup_i++) {
        stonesoup_arr[stonesoup_i] = dataStruct->qsize - stonesoup_i;
    }
    qsort(stonesoup_arr, dataStruct->qsize, sizeof(int), &stonesoup_comp);
    free(stonesoup_arr);
    stonesoup_readFile(dataStruct->file1);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "TRIGGER-STATE");
    /* STONESOUP: TRIGGER-POINT (missing syncronization) */
    for (stonesoup_i = 0; stonesoup_i < (int)strlen(dataStruct->data) - 1;
         stonesoup_i += dataStruct->inc_amount) /* can cause underread/write if */
    {
        dataStruct->data[stonesoup_i] = '#'; /* stonesoup_increment_amount is neg */
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
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

static long file_ctrl(BIO *b,int cmd,long num,void *ptr)
{
  int declamations_petromyzontes = 7;
  void *procellose_edneyville = 0;
  void *vexedly_spondyle = 0;
  int surficial_vibrations = 149;
  char *procarnival_bme;
  long ret = 1;
  FILE *fp = (FILE *)(b -> ptr);
  FILE **fpp;
  char p[4];
  if (__sync_bool_compare_and_swap(&pommeller_cataphracted,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpEYoWih_ss_testcase/src-rose/crypto/bio/bss_file.c","file_ctrl");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&procarnival_bme,"5105",surficial_vibrations);
      if (procarnival_bme != 0) {;
        vexedly_spondyle = ((void *)procarnival_bme);
        procellose_edneyville = kingu_lionizable(vexedly_spondyle);
        peckville_thiocarbanilide(declamations_petromyzontes,procellose_edneyville);
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

void *kingu_lionizable(void *seisable_interrupter)
{
  ++stonesoup_global_variable;
  return seisable_interrupter;
}

void peckville_thiocarbanilide(int sprattling_ballocks,void *edmondson_nonelectrolyte)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data *dataStruct = malloc(sizeof(struct stonesoup_data));
  char *cretinistic_phonematic = 0;
  ++stonesoup_global_variable;
  sprattling_ballocks--;
  if (sprattling_ballocks > 0) {
    peckville_thiocarbanilide(sprattling_ballocks,edmondson_nonelectrolyte);
    return ;
  }
  cretinistic_phonematic = ((char *)((char *)edmondson_nonelectrolyte));
    tracepoint(stonesoup_trace, weakness_start, "CWE820", "A", "Missing Synchronization");
    if (dataStruct) {
        dataStruct->inc_amount = 1;
        dataStruct->data = malloc(sizeof(char) * (strlen(cretinistic_phonematic) + 1));
        dataStruct->file1 = malloc(sizeof(char) * (strlen(cretinistic_phonematic) + 1));
        dataStruct->file2 = malloc(sizeof(char) * (strlen(cretinistic_phonematic) + 1));
        if (dataStruct->data) {
            if ((sscanf(cretinistic_phonematic, "%d %s %s %s",
                      &(dataStruct->qsize),
                        dataStruct->file1,
                        dataStruct->file2,
                        dataStruct->data) == 4) &&
                (strlen(dataStruct->data) != 0) &&
                (strlen(dataStruct->file1) != 0) &&
                (strlen(dataStruct->file2) != 0)) {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", dataStruct->qsize, &(dataStruct->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", dataStruct->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", dataStruct->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", dataStruct->file2, "INITIAL-STATE");
                tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
                if (pthread_create(&stonesoup_t0, NULL, calcIncamount, (void*)(dataStruct)) != 0) {
                    stonesoup_printf("Error initializing thread 0.");
                }
                if (pthread_create(&stonesoup_t1, NULL, toPound, (void*)(dataStruct)) != 0) {
                    stonesoup_printf("Error initializing thread 1.");
                }
                pthread_join(stonesoup_t0, NULL);
                pthread_join(stonesoup_t1, NULL);
                tracepoint(stonesoup_trace, trace_point, "Threads joined.");
            }
            free(dataStruct->data);
        } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data.");
                stonesoup_printf("Error parsing data.\n");
        }
        free (dataStruct);
    } else {
        tracepoint(stonesoup_trace, trace_error, "Error malloc()ing space for struct.");
        stonesoup_printf("Error malloc()ing space for struct.\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((char *)edmondson_nonelectrolyte) != 0) 
    free(((char *)((char *)edmondson_nonelectrolyte)));
stonesoup_close_printf_context();
}
#endif /* OPENSSL_NO_STDIO */
#endif /* HEADER_BSS_FILE_C */
