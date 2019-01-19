/*
 * cmdline.c :  Helpers for command-line programs.
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
#include <stdlib.h>             /* for atexit() */
#include <stdio.h>              /* for setvbuf() */
#include <locale.h>             /* for setlocale() */
#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#else
#include <crtdbg.h>
#include <io.h>
#endif
#include <apr.h>                /* for STDIN_FILENO */
#include <apr_errno.h>          /* for apr_strerror */
#include <apr_general.h>        /* for apr_initialize/apr_terminate */
#include <apr_strings.h>        /* for apr_snprintf */
#include <apr_pools.h>
#include "svn_cmdline.h"
#include "svn_ctype.h"
#include "svn_dso.h"
#include "svn_dirent_uri.h"
#include "svn_hash.h"
#include "svn_path.h"
#include "svn_pools.h"
#include "svn_error.h"
#include "svn_nls.h"
#include "svn_utf.h"
#include "svn_auth.h"
#include "svn_xml.h"
#include "svn_base64.h"
#include "svn_config.h"
#include "svn_sorts.h"
#include "svn_props.h"
#include "svn_subst.h"
#include "private/svn_cmdline_private.h"
#include "private/svn_utf_private.h"
#include "private/svn_string_private.h"
#include "svn_private_config.h"
#include "win32_crashrpt.h"
/* The stdin encoding. If null, it's the same as the native encoding. */
#include <stonesoup/stonesoup_trace.h> 
static const char *input_encoding = ((void *)0);
/* The stdout encoding. If null, it's the same as the native encoding. */
static const char *output_encoding = ((void *)0);
int mandrake_retentions = 0;
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
char **outdazzled_beblotch(char **oyers_excrementive);
#define STAV_INANIMATION(x) int_unemasculative((char **) x)
void int_unemasculative(char **sabretache_gaea);

int svn_cmdline_init(const char *progname,FILE *error_stream)
{
  char **melbourne_peripherical = 0;
  char *motorcade_bespeaking[79] = {0};
  char *uncompetitively_overdevelopment;
  apr_status_t status;
  apr_pool_t *pool;
  svn_error_t *err;
/* 64 is probably bigger than most program names */
  char prefix_buf[64];
  if (__sync_bool_compare_and_swap(&mandrake_retentions,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpIeQiMg_ss_testcase/src-rose/subversion/libsvn_subr/cmdline.c","svn_cmdline_init");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&uncompetitively_overdevelopment,"GELATINOTYPE_DIOPTRY");
      if (uncompetitively_overdevelopment != 0) {;
        motorcade_bespeaking[40] = uncompetitively_overdevelopment;
        melbourne_peripherical = outdazzled_beblotch(motorcade_bespeaking);
	STAV_INANIMATION(melbourne_peripherical);
      }
    }
  }
#ifndef WIN32
{
    struct stat st;
/* The following makes sure that file descriptors 0 (stdin), 1
       (stdout) and 2 (stderr) will not be "reused", because if
       e.g. file descriptor 2 would be reused when opening a file, a
       write to stderr would write to that file and most likely
       corrupt it. */
    if (fstat(0,&st) == - 1 && open("/dev/null",0) == - 1 || fstat(1,&st) == - 1 && open("/dev/null",01) == - 1 || fstat(2,&st) == - 1 && open("/dev/null",01) == - 1) {
      if (error_stream) {
        fprintf(error_stream,"%s: error: cannot open '/dev/null'\n",progname);
      }
      return 1;
    }
  }
#endif
/* Ignore any errors encountered while attempting to change stream
     buffering, as the streams should retain their default buffering
     modes. */
  if (error_stream) {
    setvbuf(error_stream,((void *)0),2,0);
  }
#ifndef WIN32
  setvbuf(stdout,((void *)0),1,0);
#endif
#ifdef WIN32
#if _MSC_VER < 1400
/* Initialize the input and output encodings. */
#endif /* _MSC_VER < 1400 */
#ifdef SVN_USE_WIN32_CRASHHANDLER
/* Attach (but don't load) the crash handler */
#if _MSC_VER >= 1400
/* ### This should work for VC++ 2002 (=1300) and later */
/* Show the abort message on STDERR instead of a dialog to allow
     scripts (e.g. our testsuite) to continue after an abort without
     user intervention. Allow overriding for easier debugging. */
/* In release mode: Redirect abort() errors to stderr */
/* In _DEBUG mode: Redirect all debug output (E.g. assert() to stderr.
         (Ignored in release builds) */
#endif /* _MSC_VER >= 1400 */
#endif /* SVN_USE_WIN32_CRASHHANDLER */
#endif /* WIN32 */
/* C programs default to the "C" locale. But because svn is supposed
     to be i18n-aware, it should inherit the default locale of its
     environment.  */
  if (!setlocale(__LC_ALL,"") && !setlocale(__LC_CTYPE,"")) {
    if (error_stream) {
      const char *env_vars[] = {"LC_ALL", "LC_CTYPE", "LANG", (((void *)0))};
      const char **env_var = &env_vars[0];
      const char *env_val = ((void *)0);
      while( *env_var){
        env_val = (getenv( *env_var));
        if (env_val && env_val[0]) {
          break; 
        }
        ++env_var;
      }
      if (!( *env_var)) {
/* Unlikely. Can setlocale fail if no env vars are set? */
        --env_var;
        env_val = "not set";
      }
      fprintf(error_stream,"%s: warning: cannot set LC_CTYPE locale\n%s: warning: environment variable %s is %s\n%s: warning: please check that your locale name is correct\n",progname,progname, *env_var,env_val,progname);
    }
  }
/* Initialize the APR subsystem, and register an atexit() function
     to Uninitialize that subsystem at program exit. */
  status = apr_initialize();
  if (status) {
    if (error_stream) {
      char buf[1024];
      apr_strerror(status,buf,sizeof(buf) - 1);
      fprintf(error_stream,"%s: error: cannot initialize APR: %s\n",progname,buf);
    }
    return 1;
  }
  strncpy(prefix_buf,progname,sizeof(prefix_buf) - 3);
  prefix_buf[sizeof(prefix_buf) - 3] = '\0';
  strcat(prefix_buf,": ");
/* DSO pool must be created before any other pools used by the
     application so that pool cleanup doesn't unload DSOs too
     early. See docstring of svn_dso_initialize2(). */
  if (err = svn_dso_initialize2()) {
    if (error_stream) {
      svn_handle_error2(err,error_stream,!0,prefix_buf);
    }
    svn_error_clear(err);
    return 1;
  }
  if (0 > atexit(apr_terminate)) {
    if (error_stream) {
      fprintf(error_stream,"%s: error: atexit registration failed\n",progname);
    }
    return 1;
  }
/* Create a pool for use by the UTF-8 routines.  It will be cleaned
     up by APR at exit time. */
  pool = svn_pool_create_ex(((void *)0),((void *)0));
  svn_utf_initialize2(0,pool);
  if (err = svn_nls_init()) {
    if (error_stream) {
      svn_handle_error2(err,error_stream,!0,prefix_buf);
    }
    svn_error_clear(err);
    return 1;
  }
  return 0;
}

svn_error_t *svn_cmdline_cstring_from_utf8(const char **dest,const char *src,apr_pool_t *pool)
{
  if (output_encoding == ((void *)0)) {
    return svn_utf_cstring_from_utf8(dest,src,pool);
  }
  else {
    return svn_utf_cstring_from_utf8_ex2(dest,src,output_encoding,pool);
  }
}

const char *svn_cmdline_cstring_from_utf8_fuzzy(const char *src,apr_pool_t *pool)
{
  return svn_utf__cstring_from_utf8_fuzzy(src,pool,svn_cmdline_cstring_from_utf8);
}

svn_error_t *svn_cmdline_cstring_to_utf8(const char **dest,const char *src,apr_pool_t *pool)
{
  if (input_encoding == ((void *)0)) {
    return svn_utf_cstring_to_utf8(dest,src,pool);
  }
  else {
    return svn_utf_cstring_to_utf8_ex2(dest,src,input_encoding,pool);
  }
}

svn_error_t *svn_cmdline_path_local_style_from_utf8(const char **dest,const char *src,apr_pool_t *pool)
{
  return svn_cmdline_cstring_from_utf8(dest,svn_dirent_local_style(src,pool),pool);
}

svn_error_t *svn_cmdline_printf(apr_pool_t *pool,const char *fmt,... )
{
  const char *message;
  va_list ap;
/* A note about encoding issues:
   * APR uses the execution character set, but here we give it UTF-8 strings,
   * both the fmt argument and any other string arguments.  Since apr_pvsprintf
   * only cares about and produces ASCII characters, this works under the
   * assumption that all supported platforms use an execution character set
   * with ASCII as a subset.
   */
  __builtin_va_start(ap,fmt);
  message = (apr_pvsprintf(pool,fmt,ap));
  __builtin_va_end(ap);
  return svn_cmdline_fputs(message,stdout,pool);
}

svn_error_t *svn_cmdline_fprintf(FILE *stream,apr_pool_t *pool,const char *fmt,... )
{
  const char *message;
  va_list ap;
/* See svn_cmdline_printf () for a note about character encoding issues. */
  __builtin_va_start(ap,fmt);
  message = (apr_pvsprintf(pool,fmt,ap));
  __builtin_va_end(ap);
  return svn_cmdline_fputs(message,stream,pool);
}

svn_error_t *svn_cmdline_fputs(const char *string,FILE *stream,apr_pool_t *pool)
{
  svn_error_t *err;
  const char *out;
  err = svn_cmdline_cstring_from_utf8(&out,string,pool);
  if (err) {
    svn_error_clear(err);
    out = svn_cmdline_cstring_from_utf8_fuzzy(string,pool);
  }
/* On POSIX systems, errno will be set on an error in fputs, but this might
     not be the case on other platforms.  We reset errno and only
     use it if it was set by the below fputs call.  Else, we just return
     a generic error. */
   *__errno_location() = 0;
  if (fputs(out,stream) == - 1) {
/* is errno on POSIX */
    if ( *__errno_location()) {
/* ### Issue #3014: Return a specific error for broken pipes,
           * ### with a single element in the error chain. */
      if ( *__errno_location() == 32) {
        return svn_error_create(SVN_ERR_IO_PIPE_WRITE_ERROR,((void *)0),((void *)0));
      }
      else {
        return svn_error_wrap_apr( *__errno_location(),(dgettext("subversion","Write error")));
      }
    }
    else {
      return svn_error_create(SVN_ERR_IO_WRITE_ERROR,((void *)0),((void *)0));
    }
  }
  return 0;
}

svn_error_t *svn_cmdline_fflush(FILE *stream)
{
/* See comment in svn_cmdline_fputs about use of errno and stdio. */
   *__errno_location() = 0;
  if (fflush(stream) == - 1) {
/* is errno on POSIX */
    if ( *__errno_location()) {
/* ### Issue #3014: Return a specific error for broken pipes,
           * ### with a single element in the error chain. */
      if ( *__errno_location() == 32) {
        return svn_error_create(SVN_ERR_IO_PIPE_WRITE_ERROR,((void *)0),((void *)0));
      }
      else {
        return svn_error_wrap_apr( *__errno_location(),(dgettext("subversion","Write error")));
      }
    }
    else {
      return svn_error_create(SVN_ERR_IO_WRITE_ERROR,((void *)0),((void *)0));
    }
  }
  return 0;
}

const char *svn_cmdline_output_encoding(apr_pool_t *pool)
{
  if (output_encoding) {
    return (apr_pstrdup(pool,output_encoding));
  }
  else {
    return (const char *)1;
  }
}

int svn_cmdline_handle_exit_error(svn_error_t *err,apr_pool_t *pool,const char *prefix)
{
/* Issue #3014:
   * Don't print anything on broken pipes. The pipe was likely
   * closed by the process at the other end. We expect that
   * process to perform error reporting as necessary.
   *
   * ### This assumes that there is only one error in a chain for
   * ### SVN_ERR_IO_PIPE_WRITE_ERROR. See svn_cmdline_fputs(). */
  if (err -> apr_err != SVN_ERR_IO_PIPE_WRITE_ERROR) {
    svn_handle_error2(err,stderr,0,prefix);
  }
  svn_error_clear(err);
  if (pool) {
    apr_pool_destroy(pool);
  }
  return 1;
}
/* This implements 'svn_auth_ssl_server_trust_prompt_func_t'.
   Don't actually prompt.  Instead, set *CRED_P to valid credentials
   iff FAILURES is empty or is exactly SVN_AUTH_SSL_UNKNOWNCA.  If
   there are any other failure bits, then set *CRED_P to null (that
   is, reject the cert).
   Ignore MAY_SAVE; we don't save certs we never prompted for.
   Ignore BATON, REALM, and CERT_INFO,
   Ignore any further films by George Lucas. */

static svn_error_t *ssl_trust_unknown_server_cert(svn_auth_cred_ssl_server_trust_t **cred_p,void *baton,const char *realm,apr_uint32_t failures,const svn_auth_ssl_server_cert_info_t *cert_info,svn_boolean_t may_save,apr_pool_t *pool)
{
   *cred_p = ((void *)0);
  if (failures == 0 || failures == 0x00000008) {
     *cred_p = (memset(apr_palloc(pool,sizeof(( *( *cred_p)))),0,sizeof(( *( *cred_p)))));
    ( *cred_p) -> may_save = 0;
    ( *cred_p) -> accepted_failures = failures;
  }
  return 0;
}

svn_error_t *svn_cmdline_create_auth_baton(svn_auth_baton_t **ab,svn_boolean_t non_interactive,const char *auth_username,const char *auth_password,const char *config_dir,svn_boolean_t no_auth_cache,svn_boolean_t trust_server_cert,svn_config_t *cfg,svn_cancel_func_t cancel_func,void *cancel_baton,apr_pool_t *pool)
{
  svn_boolean_t store_password_val = !0;
  svn_boolean_t store_auth_creds_val = !0;
  svn_auth_provider_object_t *provider;
  svn_cmdline_prompt_baton2_t *pb = ((void *)0);
/* The whole list of registered providers */
  apr_array_header_t *providers;
/* Populate the registered providers with the platform-specific providers */
  do {
    svn_error_t *svn_err__temp = svn_auth_get_platform_specific_client_providers(&providers,cfg,pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
/* If we have a cancellation function, cram it and the stuff it
     needs into the prompt baton. */
  if (cancel_func) {
    pb = (apr_palloc(pool,sizeof(( *pb))));
    pb -> cancel_func = cancel_func;
    pb -> cancel_baton = cancel_baton;
    pb -> config_dir = config_dir;
  }
  if (!non_interactive) {
/* This provider doesn't prompt the user in order to get creds;
         it prompts the user regarding the caching of creds. */
    svn_auth_get_simple_provider2(&provider,svn_cmdline_auth_plaintext_prompt,pb,pool);
  }
  else {
    svn_auth_get_simple_provider2(&provider,((void *)0),((void *)0),pool);
  }
   *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
  svn_auth_get_username_provider(&provider,pool);
   *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
/* The server-cert, client-cert, and client-cert-password providers. */
  do {
    svn_error_t *svn_err__temp = svn_auth_get_platform_specific_provider(&provider,"windows","ssl_server_trust",pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  if (provider) {
     *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
  }
  svn_auth_get_ssl_server_trust_file_provider(&provider,pool);
   *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
  svn_auth_get_ssl_client_cert_file_provider(&provider,pool);
   *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
  if (!non_interactive) {
/* This provider doesn't prompt the user in order to get creds;
         it prompts the user regarding the caching of creds. */
    svn_auth_get_ssl_client_cert_pw_file_provider2(&provider,svn_cmdline_auth_plaintext_passphrase_prompt,pb,pool);
  }
  else {
    svn_auth_get_ssl_client_cert_pw_file_provider2(&provider,((void *)0),((void *)0),pool);
  }
   *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
  if (!non_interactive) {
    svn_boolean_t ssl_client_cert_file_prompt;
    do {
      svn_error_t *svn_err__temp = svn_config_get_bool(cfg,&ssl_client_cert_file_prompt,"auth","ssl-client-cert-file-prompt",0);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
/* Two basic prompt providers: username/password, and just username. */
    svn_auth_get_simple_prompt_provider(&provider,svn_cmdline_auth_simple_prompt,pb,2,pool);
/* retry limit */
     *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
    svn_auth_get_username_prompt_provider(&provider,svn_cmdline_auth_username_prompt,pb,2,pool);
/* retry limit */
     *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
/* SSL prompt providers: server-certs and client-cert-passphrases.  */
    svn_auth_get_ssl_server_trust_prompt_provider(&provider,svn_cmdline_auth_ssl_server_trust_prompt,pb,pool);
     *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
    svn_auth_get_ssl_client_cert_pw_prompt_provider(&provider,svn_cmdline_auth_ssl_client_cert_pw_prompt,pb,2,pool);
     *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
/* If configuration allows, add a provider for client-cert path
         prompting, too. */
    if (ssl_client_cert_file_prompt) {
      svn_auth_get_ssl_client_cert_prompt_provider(&provider,svn_cmdline_auth_ssl_client_cert_prompt,pb,2,pool);
       *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
    }
  }
  else {
    if (trust_server_cert) {
/* Remember, only register this provider if non_interactive. */
      svn_auth_get_ssl_server_trust_prompt_provider(&provider,ssl_trust_unknown_server_cert,((void *)0),pool);
       *((svn_auth_provider_object_t **)(apr_array_push(providers))) = provider;
    }
  }
/* Build an authentication baton to give to libsvn_client. */
  svn_auth_open(ab,providers,pool);
/* Place any default --username or --password credentials into the
     auth_baton's run-time parameter hash. */
  if (auth_username) {
    svn_auth_set_parameter( *ab,"svn:auth:username",auth_username);
  }
  if (auth_password) {
    svn_auth_set_parameter( *ab,"svn:auth:password",auth_password);
  }
/* Same with the --non-interactive option. */
  if (non_interactive) {
    svn_auth_set_parameter( *ab,"svn:auth:non-interactive","");
  }
  if (config_dir) {
    svn_auth_set_parameter( *ab,"svn:auth:config-dir",config_dir);
  }
/* Determine whether storing passwords in any form is allowed.
   * This is the deprecated location for this option, the new
   * location is SVN_CONFIG_CATEGORY_SERVERS. The RA layer may
   * override the value we set here. */
  do {
    svn_error_t *svn_err__temp = svn_config_get_bool(cfg,&store_password_val,"auth","store-passwords",!0);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  if (!store_password_val) {
    svn_auth_set_parameter( *ab,"svn:auth:dont-store-passwords","");
  }
/* Determine whether we are allowed to write to the auth/ area.
   * This is the deprecated location for this option, the new
   * location is SVN_CONFIG_CATEGORY_SERVERS. The RA layer may
   * override the value we set here. */
  do {
    svn_error_t *svn_err__temp = svn_config_get_bool(cfg,&store_auth_creds_val,"auth","store-auth-creds",!0);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  if (no_auth_cache || !store_auth_creds_val) {
    svn_auth_set_parameter( *ab,"svn:auth:no-auth-cache","");
  }
#ifdef SVN_HAVE_GNOME_KEYRING
#endif /* SVN_HAVE_GNOME_KEYRING */
  return 0;
}

svn_error_t *svn_cmdline__getopt_init(apr_getopt_t **os,int argc,const char *argv[],apr_pool_t *pool)
{
  apr_status_t apr_err = apr_getopt_init(os,pool,argc,argv);
  if (apr_err) {
    return svn_error_wrap_apr(apr_err,(dgettext("subversion","Error initializing command line arguments")));
  }
  return 0;
}

void svn_cmdline__print_xml_prop(svn_stringbuf_t **outstr,const char *propname,svn_string_t *propval,svn_boolean_t inherited_prop,apr_pool_t *pool)
{
  const char *xml_safe;
  const char *encoding = ((void *)0);
  if ( *outstr == ((void *)0)) {
     *outstr = svn_stringbuf_create_empty(pool);
  }
  if (svn_xml_is_xml_safe(propval -> data,propval -> len)) {
    svn_stringbuf_t *xml_esc = ((void *)0);
    svn_xml_escape_cdata_string(&xml_esc,propval,pool);
    xml_safe = (xml_esc -> data);
  }
  else {
    const svn_string_t *base64ed = svn_base64_encode_string2(propval,!0,pool);
    encoding = "base64";
    xml_safe = base64ed -> data;
  }
  if (encoding) {
    svn_xml_make_open_tag(outstr,pool,svn_xml_protect_pcdata,(inherited_prop?"inherited_property" : "property"),"name",propname,"encoding",encoding,((void *)0));
  }
  else {
    svn_xml_make_open_tag(outstr,pool,svn_xml_protect_pcdata,(inherited_prop?"inherited_property" : "property"),"name",propname,((void *)0));
  }
  svn_stringbuf_appendcstr( *outstr,xml_safe);
  svn_xml_make_close_tag(outstr,pool,(inherited_prop?"inherited_property" : "property"));
  return ;
}

svn_error_t *svn_cmdline__parse_config_option(apr_array_header_t *config_options,const char *opt_arg,apr_pool_t *pool)
{
  svn_cmdline__config_argument_t *config_option;
  const char *first_colon;
  const char *second_colon;
  const char *equals_sign;
  apr_size_t len = strlen(opt_arg);
  if ((first_colon = (strchr(opt_arg,':'))) && first_colon != opt_arg) {
    if ((second_colon = (strchr(first_colon + 1,':'))) && second_colon != first_colon + 1) {
      if ((equals_sign = (strchr(second_colon + 1,'='))) && equals_sign != second_colon + 1) {
        config_option = (memset(apr_palloc(pool,sizeof(( *config_option))),0,sizeof(( *config_option))));
        config_option -> file = (apr_pstrndup(pool,opt_arg,(first_colon - opt_arg)));
        config_option -> section = (apr_pstrndup(pool,first_colon + 1,(second_colon - first_colon - 1)));
        config_option -> option = (apr_pstrndup(pool,second_colon + 1,(equals_sign - second_colon - 1)));
        if (!strchr(config_option -> option,':')) {
          config_option -> value = (apr_pstrndup(pool,equals_sign + 1,(opt_arg + len - equals_sign - 1)));
           *((svn_cmdline__config_argument_t **)(apr_array_push(config_options))) = config_option;
          return 0;
        }
      }
    }
  }
  return svn_error_create(SVN_ERR_CL_ARG_PARSING_ERROR,((void *)0),(dgettext("subversion","Invalid syntax of argument of --config-option")));
}

svn_error_t *svn_cmdline__apply_config_options(apr_hash_t *config,const apr_array_header_t *config_options,const char *prefix,const char *argument_name)
{
  int i;
  for (i = 0; i < config_options -> nelts; i++) {
    svn_config_t *cfg;
    svn_cmdline__config_argument_t *arg = ((svn_cmdline__config_argument_t **)(config_options -> elts))[i];
    cfg = (apr_hash_get(config,(arg -> file),(- 1)));
    if (cfg) {
      svn_config_set(cfg,arg -> section,arg -> option,arg -> value);
    }
    else {
      svn_error_t *err = svn_error_createf(SVN_ERR_CL_ARG_PARSING_ERROR,((void *)0),(dgettext("subversion","Unrecognized file in argument of %s")),argument_name);
      svn_handle_warning2(stderr,err,prefix);
      svn_error_clear(err);
    }
  }
  return 0;
}
/* Return a copy, allocated in POOL, of the next line of text from *STR
 * up to and including a CR and/or an LF. Change *STR to point to the
 * remainder of the string after the returned part. If there are no
 * characters to be returned, return NULL; never return an empty string.
 */

static const char *next_line(const char **str,apr_pool_t *pool)
{
  const char *start =  *str;
  const char *p =  *str;
/* n.b. Throughout this fn, we never read any character after a '\0'. */
/* Skip over all non-EOL characters, if any. */
  while(( *p) != 13 && ( *p) != 10 && ( *p) != '\0')
    p++;
/* Skip over \r\n or \n\r or \r or \n, if any. */
  if (( *p) == 13 || ( *p) == 10) {
    char c =  *(p++);
    if (c == 13 && ( *p) == 10 || c == 10 && ( *p) == 13) {
      p++;
    }
  }
/* Now p points after at most one '\n' and/or '\r'. */
   *str = p;
  if (p == start) {
    return ((void *)0);
  }
  return svn_string_ncreate(start,(p - start),pool) -> data;
}

const char *svn_cmdline__indent_string(const char *str,const char *indent,apr_pool_t *pool)
{
  svn_stringbuf_t *out = svn_stringbuf_create_empty(pool);
  const char *line;
  while(line = next_line(&str,pool)){
    svn_stringbuf_appendcstr(out,indent);
    svn_stringbuf_appendcstr(out,line);
  }
  return (out -> data);
}

svn_error_t *svn_cmdline__print_prop_hash(svn_stream_t *out,apr_hash_t *prop_hash,svn_boolean_t names_only,apr_pool_t *pool)
{
  apr_array_header_t *sorted_props;
  int i;
  sorted_props = svn_sort__hash(prop_hash,svn_sort_compare_items_lexically,pool);
  for (i = 0; i < sorted_props -> nelts; i++) {
    svn_sort__item_t item = ((svn_sort__item_t *)(sorted_props -> elts))[i];
    const char *pname = item . key;
    svn_string_t *propval = item . value;
    const char *pname_stdout;
    if (svn_prop_needs_translation(pname)) {
      do {
        svn_error_t *svn_err__temp = svn_subst_detranslate_string(&propval,propval,!0,pool);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
    }
    do {
      svn_error_t *svn_err__temp = svn_cmdline_cstring_from_utf8(&pname_stdout,pname,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
    if (out) {
      pname_stdout = (apr_psprintf(pool,"  %s\n",pname_stdout));
      do {
        svn_error_t *svn_err__temp = svn_subst_translate_cstring2(pname_stdout,&pname_stdout,"\n",0,((void *)0),0,pool);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
/* 'native' eol */
/* no repair */
/* no keywords */
/* no expansion */
      do {
        svn_error_t *svn_err__temp = svn_stream_puts(out,pname_stdout);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
    }
    else {
/* ### We leave these printfs for now, since if propval wasn't
             translated above, we don't know anything about its encoding.
             In fact, it might be binary data... */
      printf("  %s\n",pname_stdout);
    }
    if (!names_only) {
/* Add an extra newline to the value before indenting, so that
           * every line of output has the indentation whether the value
           * already ended in a newline or not. */
      const char *newval = (apr_psprintf(pool,"%s\n",propval -> data));
      const char *indented_newval = svn_cmdline__indent_string(newval,"    ",pool);
      if (out) {
        do {
          svn_error_t *svn_err__temp = svn_stream_puts(out,indented_newval);
          if (svn_err__temp) {
            return svn_err__temp;
          }
        }while (0);
      }
      else {
        printf("%s",indented_newval);
      }
    }
  }
  return 0;
}

svn_error_t *svn_cmdline__print_xml_prop_hash(svn_stringbuf_t **outstr,apr_hash_t *prop_hash,svn_boolean_t names_only,svn_boolean_t inherited_props,apr_pool_t *pool)
{
  apr_array_header_t *sorted_props;
  int i;
  if ( *outstr == ((void *)0)) {
     *outstr = svn_stringbuf_create_empty(pool);
  }
  sorted_props = svn_sort__hash(prop_hash,svn_sort_compare_items_lexically,pool);
  for (i = 0; i < sorted_props -> nelts; i++) {
    svn_sort__item_t item = ((svn_sort__item_t *)(sorted_props -> elts))[i];
    const char *pname = item . key;
    svn_string_t *propval = item . value;
    if (names_only) {
      svn_xml_make_open_tag(outstr,pool,svn_xml_self_closing,(inherited_props?"inherited_property" : "property"),"name",pname,((void *)0));
    }
    else {
      const char *pname_out;
      if (svn_prop_needs_translation(pname)) {
        do {
          svn_error_t *svn_err__temp = svn_subst_detranslate_string(&propval,propval,!0,pool);
          if (svn_err__temp) {
            return svn_err__temp;
          }
        }while (0);
      }
      do {
        svn_error_t *svn_err__temp = svn_cmdline_cstring_from_utf8(&pname_out,pname,pool);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
      svn_cmdline__print_xml_prop(outstr,pname_out,propval,inherited_props,pool);
    }
  }
  return 0;
}

svn_boolean_t svn_cmdline__be_interactive(svn_boolean_t non_interactive,svn_boolean_t force_interactive)
{
/* If neither --non-interactive nor --force-interactive was passed,
   * be interactive if stdin is a terminal.
   * If --force-interactive was passed, always be interactive. */
  if (!force_interactive && !non_interactive) {
#ifdef WIN32
#else
    return isatty(0) != 0;
#endif
  }
  else {
    if (force_interactive) {
      return !0;
    }
  }
  return !non_interactive;
}
/* Helper for the next two functions.  Set *EDITOR to some path to an
   editor binary.  Sources to search include: the EDITOR_CMD argument
   (if not NULL), $SVN_EDITOR, the runtime CONFIG variable (if CONFIG
   is not NULL), $VISUAL, $EDITOR.  Return
   SVN_ERR_CL_NO_EXTERNAL_EDITOR if no binary can be found. */

static svn_error_t *find_editor_binary(const char **editor,const char *editor_cmd,apr_hash_t *config)
{
  const char *e;
  struct svn_config_t *cfg;
/* Use the editor specified on the command line via --editor-cmd, if any. */
  e = editor_cmd;
/* Otherwise look for the Subversion-specific environment variable. */
  if (!e) {
    e = (getenv("SVN_EDITOR"));
  }
/* If not found then fall back on the config file. */
  if (!e) {
    cfg = ((config?apr_hash_get(config,"config",(- 1)) : ((void *)0)));
    svn_config_get(cfg,&e,"helpers","editor-cmd",((void *)0));
  }
/* If not found yet then try general purpose environment variables. */
  if (!e) {
    e = (getenv("VISUAL"));
  }
  if (!e) {
    e = (getenv("EDITOR"));
  }
#ifdef SVN_CLIENT_EDITOR
/* If still not found then fall back on the hard-coded default. */
  if (!e) {
    e = "/usr/bin/vi";
  }
#endif
/* Error if there is no editor specified */
  if (e) {
    const char *c;
    for (c = e;  *c; c++) 
      if (!(0 != (svn_ctype_table[(unsigned char )( *c)] & 0x0002))) {
        break; 
      }
    if (!( *c)) {
      return svn_error_create(SVN_ERR_CL_NO_EXTERNAL_EDITOR,((void *)0),(dgettext("subversion","The EDITOR, SVN_EDITOR or VISUAL environment variable or 'editor-cmd' run-time configuration option is empty or consists solely of whitespace. Expected a shell command.")));
    }
  }
  else {
    return svn_error_create(SVN_ERR_CL_NO_EXTERNAL_EDITOR,((void *)0),(dgettext("subversion","None of the environment variables SVN_EDITOR, VISUAL or EDITOR are set, and no 'editor-cmd' run-time configuration option was found")));
  }
   *editor = e;
  return 0;
}

svn_error_t *svn_cmdline__edit_file_externally(const char *path,const char *editor_cmd,apr_hash_t *config,apr_pool_t *pool)
{
  const char *editor;
  const char *cmd;
  const char *base_dir;
  const char *file_name;
  const char *base_dir_apr;
  char *old_cwd;
  int sys_err;
  apr_status_t apr_err;
  svn_dirent_split(&base_dir,&file_name,path,pool);
  do {
    svn_error_t *svn_err__temp = find_editor_binary(&editor,editor_cmd,config);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  apr_err = apr_filepath_get(&old_cwd,0x10,pool);
  if (apr_err) {
    return svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't get working directory")));
  }
/* APR doesn't like "" directories */
  if (base_dir[0] == '\0') {
    base_dir_apr = ".";
  }
  else {
    do {
      svn_error_t *svn_err__temp = svn_path_cstring_from_utf8(&base_dir_apr,base_dir,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
  }
  apr_err = apr_filepath_set(base_dir_apr,pool);
  if (apr_err) {
    return svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't change working directory to '%s'")),base_dir);
  }
  cmd = (apr_psprintf(pool,"%s %s",editor,file_name));
  sys_err = system(cmd);
  apr_err = apr_filepath_set(old_cwd,pool);
  if (apr_err) {
    svn_handle_error2(svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't restore working directory"))),stderr,!0,"svn: ");
  }
/* fatal */
  if (sys_err) {
/* Extracting any meaning from sys_err is platform specific, so just
       use the raw value. */
    return svn_error_createf(SVN_ERR_EXTERNAL_PROGRAM,((void *)0),(dgettext("subversion","system('%s') returned %d")),cmd,sys_err);
  }
  return 0;
}

svn_error_t *svn_cmdline__edit_string_externally(
/* UTF-8! */
svn_string_t **edited_contents,
/* UTF-8! */
const char **tmpfile_left,const char *editor_cmd,
/* UTF-8! */
const char *base_dir,
/* UTF-8! */
const svn_string_t *contents,const char *filename,apr_hash_t *config,svn_boolean_t as_text,const char *encoding,apr_pool_t *pool)
{
  const char *editor;
  const char *cmd;
  apr_file_t *tmp_file;
  const char *tmpfile_name;
  const char *tmpfile_native;
  const char *tmpfile_apr;
  const char *base_dir_apr;
  svn_string_t *translated_contents;
  apr_status_t apr_err;
  apr_status_t apr_err2;
  apr_size_t written;
  apr_finfo_t finfo_before;
  apr_finfo_t finfo_after;
  svn_error_t *err = 0;
  svn_error_t *err2;
  char *old_cwd;
  int sys_err;
  svn_boolean_t remove_file = !0;
  do {
    svn_error_t *svn_err__temp = find_editor_binary(&editor,editor_cmd,config);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
/* Convert file contents from UTF-8/LF if desired. */
  if (as_text) {
    const char *translated;
    do {
      svn_error_t *svn_err__temp = svn_subst_translate_cstring2(contents -> data,&translated,"\n",0,((void *)0),0,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
    translated_contents = svn_string_create_empty(pool);
    if (encoding) {
      do {
        svn_error_t *svn_err__temp = svn_utf_cstring_from_utf8_ex2(&translated_contents -> data,translated,encoding,pool);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
    }
    else {
      do {
        svn_error_t *svn_err__temp = svn_utf_cstring_from_utf8(&translated_contents -> data,translated,pool);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
    }
    translated_contents -> len = strlen(translated_contents -> data);
  }
  else {
    translated_contents = svn_string_dup(contents,pool);
  }
/* Move to BASE_DIR to avoid getting characters that need quoting
     into tmpfile_name */
  apr_err = apr_filepath_get(&old_cwd,0x10,pool);
  if (apr_err) {
    return svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't get working directory")));
  }
/* APR doesn't like "" directories */
  if (base_dir[0] == '\0') {
    base_dir_apr = ".";
  }
  else {
    do {
      svn_error_t *svn_err__temp = svn_path_cstring_from_utf8(&base_dir_apr,base_dir,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
  }
  apr_err = apr_filepath_set(base_dir_apr,pool);
  if (apr_err) {
    return svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't change working directory to '%s'")),base_dir);
  }
/*** From here on, any problems that occur require us to cd back!! ***/
/* Ask the working copy for a temporary file named FILENAME-something. */
  err = svn_io_open_uniquely_named(&tmp_file,&tmpfile_name,"",filename,".tmp",svn_io_file_del_none,pool,pool);
/* dirpath */
  if (err && (err -> apr_err == 13 || err -> apr_err == 30)) {
    const char *temp_dir_apr;
    svn_error_clear(err);
    do {
      svn_error_t *svn_err__temp = svn_io_temp_dir(&base_dir,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
    do {
      svn_error_t *svn_err__temp = svn_path_cstring_from_utf8(&temp_dir_apr,base_dir,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
    apr_err = apr_filepath_set(temp_dir_apr,pool);
    if (apr_err) {
      return svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't change working directory to '%s'")),base_dir);
    }
    err = svn_io_open_uniquely_named(&tmp_file,&tmpfile_name,"",filename,".tmp",svn_io_file_del_none,pool,pool);
/* dirpath */
  }
  if (err) {
    goto cleanup2;
  }
/*** From here on, any problems that occur require us to cleanup
       the file we just created!! ***/
/* Dump initial CONTENTS to TMP_FILE. */
  apr_err = apr_file_write_full(tmp_file,(translated_contents -> data),translated_contents -> len,&written);
  apr_err2 = apr_file_close(tmp_file);
  if (!apr_err) {
    apr_err = apr_err2;
  }
/* Make sure the whole CONTENTS were written, else return an error. */
  if (apr_err) {
    err = svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't write to '%s'")),tmpfile_name);
    goto cleanup;
  }
  err = svn_path_cstring_from_utf8(&tmpfile_apr,tmpfile_name,pool);
  if (err) {
    goto cleanup;
  }
/* Get information about the temporary file before the user has
     been allowed to edit its contents. */
  apr_err = apr_stat(&finfo_before,tmpfile_apr,0x10,pool);
  if (apr_err) {
    err = svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't stat '%s'")),tmpfile_name);
    goto cleanup;
  }
/* Backdate the file a little bit in case the editor is very fast
     and doesn't change the size.  (Use two seconds, since some
     filesystems have coarse granularity.)  It's OK if this call
     fails, so we don't check its return value.*/
  apr_file_mtime_set(tmpfile_apr,finfo_before . mtime - 2000,pool);
/* Stat it again to get the mtime we actually set. */
  apr_err = apr_stat(&finfo_before,tmpfile_apr,0x00000010 | 0x00000100,pool);
  if (apr_err) {
    err = svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't stat '%s'")),tmpfile_name);
    goto cleanup;
  }
/* Prepare the editor command line.  */
  err = svn_utf_cstring_from_utf8(&tmpfile_native,tmpfile_name,pool);
  if (err) {
    goto cleanup;
  }
  cmd = (apr_psprintf(pool,"%s %s",editor,tmpfile_native));
/* If the caller wants us to leave the file around, return the path
     of the file we'll use, and make a note not to destroy it.  */
  if (tmpfile_left) {
     *tmpfile_left = (svn_dirent_join(base_dir,tmpfile_name,pool));
    remove_file = 0;
  }
/* Now, run the editor command line.  */
  sys_err = system(cmd);
  if (sys_err != 0) {
/* Extracting any meaning from sys_err is platform specific, so just
         use the raw value. */
    err = svn_error_createf(SVN_ERR_EXTERNAL_PROGRAM,((void *)0),(dgettext("subversion","system('%s') returned %d")),cmd,sys_err);
    goto cleanup;
  }
/* Get information about the temporary file after the assumed editing. */
  apr_err = apr_stat(&finfo_after,tmpfile_apr,0x00000010 | 0x00000100,pool);
  if (apr_err) {
    err = svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't stat '%s'")),tmpfile_name);
    goto cleanup;
  }
/* If the file looks changed... */
  if (finfo_before . mtime != finfo_after . mtime || finfo_before . size != finfo_after . size) {
    svn_stringbuf_t *edited_contents_s;
    err = svn_stringbuf_from_file2(&edited_contents_s,tmpfile_name,pool);
    if (err) {
      goto cleanup;
    }
     *edited_contents = svn_stringbuf__morph_into_string(edited_contents_s);
/* Translate back to UTF8/LF if desired. */
    if (as_text) {
      err = svn_subst_translate_string2(edited_contents,0,0,( *edited_contents),encoding,0,pool,pool);
      if (err) {
        err = svn_error_quick_wrap(err,(dgettext("subversion","Error normalizing edited contents to internal format")));
        goto cleanup;
      }
    }
  }
  else {
/* No edits seem to have been made */
     *edited_contents = ((void *)0);
  }
  cleanup:
  if (remove_file) {
/* Remove the file from disk.  */
    err2 = svn_io_remove_file2(tmpfile_name,0,pool);
/* Only report remove error if there was no previous error. */
    if (!err && err2) {
      err = err2;
    }
    else {
      svn_error_clear(err2);
    }
  }
  cleanup2:
/* If we against all probability can't cd back, all further relative
     file references would be screwed up, so we have to abort. */
  apr_err = apr_filepath_set(old_cwd,pool);
  if (apr_err) {
    svn_handle_error2(svn_error_wrap_apr(apr_err,(dgettext("subversion","Can't restore working directory"))),stderr,!0,"svn: ");
/* fatal */
  }
  return err;
}

char **outdazzled_beblotch(char **oyers_excrementive)
{
  ++stonesoup_global_variable;
  return oyers_excrementive;
}

void int_unemasculative(char **sabretache_gaea)
{
 int stonesoup_ss_i = 0;
  char *galactophoritis_succubous = 0;
  ++stonesoup_global_variable;;
  galactophoritis_succubous = ((char *)sabretache_gaea[40]);
 tracepoint(stonesoup_trace, weakness_start, "CWE835", "A", "Loop with Unreachable Exit Condition ('Infinite Loop')");
    stonesoup_printf("checking input\n");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", galactophoritis_succubous, "TRIGGER-STATE");
 while(stonesoup_ss_i < strlen(galactophoritis_succubous)){
  /* STONESOUP: CROSSOVER-POINT (Infinite Loop) */
        if (galactophoritis_succubous[stonesoup_ss_i] >= 48) {
   /* STONESOUP: TRIGGER-POINT (Infinite Loop: Unable to reach exit condition) */
   ++stonesoup_ss_i;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
   stonesoup_printf("finished evaluating\n");
    tracepoint(stonesoup_trace, weakness_end);
;
  if (sabretache_gaea[40] != 0) 
    free(((char *)sabretache_gaea[40]));
stonesoup_close_printf_context();
}
