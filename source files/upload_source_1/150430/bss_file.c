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
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
static int file_write(BIO *b,const char *in,int inl);
static int file_read(BIO *b,char *out,int outl);
static int file_puts(BIO *bp,const char *str);
static int file_gets(BIO *bp,char *buf,int size);
static long file_ctrl(BIO *b,int cmd,long num,void *ptr);
static int file_new(BIO *bi);
static int file_free(BIO *a);
static BIO_METHOD methods_filep = {(2 | 0x0400), ("FILE pointer"), (file_write), (file_read), (file_puts), (file_gets), (file_ctrl), (file_new), (file_free), (((void *)0))};
int jinx_kulturkampf = 0;
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
void irregeneracy_lipopexia(int counterearth_chironomic,char **gimels_sizzlingly);
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp7iH5Dd_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        tracepoint(stonesoup_trace, trace_point, "Reading from FIFO");
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Exiting readFile");
}
void waitForChange(char* file, char* sleepFile) {
    int fd;
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp7iH5Dd_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_waitForChange");
    stonesoup_printf("In waitForChange\n");
    strcat(filename, file);
    strcat(filename, ".pid");
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            stonesoup_printf("Error writing to file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Wrote .pid file");
        if (close(fd) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error closing file.");
            stonesoup_printf("Error closing file.");
        }
        stonesoup_readFile(sleepFile);
    }
}
int stonesoup_path_is_relative(char *path) {
    char *chr = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp7iH5Dd_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_path_is_relative");
    chr = strchr(path,'/');
    if (chr == 0) {
        tracepoint(stonesoup_trace, trace_point, "Path is relative");
        stonesoup_printf("Path is relative\n");
        return 1;
    } else {
        tracepoint(stonesoup_trace, trace_point, "Path is not relative");
        stonesoup_printf("Path is not relative\n");
        return 0;
    }
}
char * stonesoup_get_absolute_path(char * path) {
    char * abs_path = malloc (sizeof(char) * (strlen("/opt/stonesoup/workspace/testData/") * strlen(path) + 1));
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp7iH5Dd_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_get_absolute_path");
    if (abs_path == NULL) {
        stonesoup_printf("Cannot allocate memory for path\n");
    } else {
        stonesoup_printf("Creating absolute path\n");
        strcpy(abs_path, "/opt/stonesoup/workspace/testData/");
        strcat(abs_path, path);
    }
    return abs_path;
}
int stonesoup_isSymLink(char *file) {
    struct stat statbuf;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp7iH5Dd_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_isSymLink");
    if (lstat(file, &statbuf) < 0) { /* if error occured */
        stonesoup_printf("Error accessing path.\n");
        return 1; /* just end program */
    }
    if (S_ISLNK(statbuf.st_mode) == 1) {
        stonesoup_printf("Path is symlink.\n");
        return 1;
    }
    stonesoup_printf("Path is valid.\n");
    return 0;
}
int stonesoup_path_is_not_symlink(char * abs_path) {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp7iH5Dd_ss_testcase/src-rose/crypto/bio/bss_file.c", "stonesoup_path_is_not_symlink");
    return (stonesoup_isSymLink(abs_path) == 0);
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
  int nonaffilliated_nabalism = 7;
  char **eradiate_obligingly = 0;
  char *larbolins_traducent[82] = {0};
  char *tetrabelodon_sunfish;
  long ret = 1;
  FILE *fp = (FILE *)(b -> ptr);
  FILE **fpp;
  char p[4];
  if (__sync_bool_compare_and_swap(&jinx_kulturkampf,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp7iH5Dd_ss_testcase/src-rose/crypto/bio/bss_file.c","file_ctrl");
      stonesoup_setup_printf_context();
      tetrabelodon_sunfish = getenv("RHIZODERMIS_HANDWRITINGS");
      if (tetrabelodon_sunfish != 0) {;
        larbolins_traducent[76] = tetrabelodon_sunfish;
        eradiate_obligingly = larbolins_traducent;
        irregeneracy_lipopexia(nonaffilliated_nabalism,eradiate_obligingly);
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

void irregeneracy_lipopexia(int counterearth_chironomic,char **gimels_sizzlingly)
{
    int stonesoup_size = 0;
    FILE *stonesoup_file = 0;
    char *stonesoup_buffer = 0;
    char *stonesoup_str = 0;
    char *stonesoup_abs_path = 0;
    char *stonesoup_sleep_file = 0;
  char *antimalarial_colmesneil = 0;
  ++stonesoup_global_variable;
  counterearth_chironomic--;
  if (counterearth_chironomic > 0) {
    irregeneracy_lipopexia(counterearth_chironomic,gimels_sizzlingly);
    return ;
  }
  antimalarial_colmesneil = ((char *)gimels_sizzlingly[76]);
    tracepoint(stonesoup_trace, weakness_start, "CWE363", "A", "Race Condition Enabling Link Following");
    stonesoup_str = malloc(sizeof(char) * (strlen(antimalarial_colmesneil) + 1));
    stonesoup_sleep_file = malloc(sizeof(char) * (strlen(antimalarial_colmesneil) + 1));
    if (stonesoup_str != NULL && stonesoup_sleep_file != NULL &&
        (sscanf(antimalarial_colmesneil, "%s %s",
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
                if (stonesoup_path_is_not_symlink(stonesoup_abs_path)) {
                    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
                    /* STONESOUP: CROSSOVER-POINT (race condition enabling link following) */
                    waitForChange(stonesoup_abs_path, stonesoup_sleep_file);
                    stonesoup_file = fopen(stonesoup_abs_path,"rb");
                    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
                    if (stonesoup_file != 0) {
                        fseek(stonesoup_file,0,2);
                        stonesoup_size = ftell(stonesoup_file);
                        rewind(stonesoup_file);
                        stonesoup_buffer = ((char *)(malloc(sizeof(char ) * (stonesoup_size + 1))));
                        if (stonesoup_buffer) {
                            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
                            /* STONESOUP: TRIGGER-POINT (race condition enabling link following) */
                            fread(stonesoup_buffer,sizeof(char ),stonesoup_size,stonesoup_file);
                            stonesoup_buffer[stonesoup_size] = '\0';
                            stonesoup_printf(stonesoup_buffer);
                            fclose(stonesoup_file);
                            free(stonesoup_buffer);
                            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
                        }
                    }
                }
                free (stonesoup_abs_path);
            }
        }
        free(stonesoup_str);
    } else {
        tracepoint(stonesoup_trace, trace_point, "Error parsing input.");
        stonesoup_printf("Error parsing input.\n");
    }
;
stonesoup_close_printf_context();
}
#endif /* OPENSSL_NO_STDIO */
#endif /* HEADER_BSS_FILE_C */
