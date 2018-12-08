/*
    klogd.c - main program for Linux kernel log daemon.
    Copyright (c) 1995  Dr. G.W. Wettstein <greg@wind.rmcc.com>

    This file is part of the sysklogd package, a kernel and system log daemon.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* Includes. */
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#if !defined(__GLIBC__)
#include <linux/time.h>
#endif /* __GLIBC__ */
#include <stdarg.h>
#include <paths.h>
#include <stdlib.h>
#include "klogd.h"
#include "ksyms.h"

#define __LIBRARY__
#include <linux/unistd.h>
#if !defined(__GLIBC__)
# define __NR_ksyslog __NR_syslog
_syscall3(int,ksyslog,int, type, char *, buf, int, len);
#else
#include <sys/klog.h>
#define ksyslog klogctl
#endif

#include "my-include.h"

static int	kmsg,
		change_state = 0,
		terminate = 0,
		caught_TSTP = 0,
		reload_symbols = 0,
		console_log_level = 6;

static int	use_syscall = 0,
		one_shot = 0,
		symbol_lookup = 1,
		no_fork = 0;	/* don't fork - don't run in daemon mode */

static char	*symfile = (char *) 0,
		log_buffer[LOG_BUFFER_SIZE];

static FILE *output_file = (FILE *) 0;

static enum LOGSRC {none, proc, kernel} logsrc;

int debugging = 1;      /* JW: Set debugging on */


/* Function prototypes. */
extern int ksyslog(int type, char *buf, int len);
static void CloseLogSrc(void);
extern void restart(int sig);
extern void stop_logging(int sig);
extern void stop_daemon(int sig);
extern void reload_daemon(int sig);
static void Terminate(void);
static void ReloadSymbols(void);
static void ChangeLogging(void);
static enum LOGSRC GetKernelLogSrc(void);
static void LogLine(char *ptr, int len);

static void CloseLogSrc()

{
	/* Turn on logging of messages to console. */
  	ksyslog(7, NULL, 0);
  
        /* Shutdown the log sources. */
	switch ( logsrc )
	{
	    case kernel:
		ksyslog(0, 0, 0);
		Syslog(LOG_INFO, "Kernel logging (ksyslog) stopped.");
		break;
            case proc:
		close(kmsg);
		Syslog(LOG_INFO, "Kernel logging (proc) stopped.");
		break;
	    case none:
		break;
	}

	if ( output_file != (FILE *) 0 )
		fflush(output_file);
	return;
}


void restart(sig)
	
	int sig;

{
	signal(SIGCONT, restart);
	change_state = 1;
	caught_TSTP = 0;
	return;
}


void stop_logging(sig)

	int sig;
	
{
	signal(SIGTSTP, stop_logging);
	change_state = 1;
	caught_TSTP = 1;
	return;
}


void stop_daemon(sig)

	int sig;

{
	Terminate();
	return;
}


void reload_daemon(sig)

     int sig;

{
	change_state = 1;
	reload_symbols = 1;


	if ( sig == SIGUSR2 )
	{
		++reload_symbols;
		signal(SIGUSR2, reload_daemon);
	}
	else
		signal(SIGUSR1, reload_daemon);
		
	return;
}


static void Terminate()

{
	CloseLogSrc();
	Syslog(LOG_INFO, "Kernel log daemon terminating.");
	sleep(1);
	if ( output_file != (FILE *) 0 )
		fclose(output_file);
	closelog();
	exit(1);
}

static void ReloadSymbols()

{
	return;
}


static void ChangeLogging(void)

{
	/* Terminate kernel logging. */
	if ( terminate == 1 )
		Terminate();

	/* Indicate that something is happening. */
	Syslog(LOG_INFO, "klogd %s-%s, ---------- state change ----------\n", \
	       VERSION, PATCHLEVEL);

	/* Reload symbols. */
	if ( reload_symbols > 0 )
	{
		ReloadSymbols();
		return;
	}

	/* Stop kernel logging. */
	if ( caught_TSTP == 1 )
	{
		CloseLogSrc();
		logsrc = none;
		change_state = 0;
		return;
	}
		
	/*
	 * The rest of this function is responsible for restarting
	 * kernel logging after it was stopped.
	 *
	 * In the following section we make a decision based on the
	 * kernel log state as to what is causing us to restart.  Somewhat
	 * groady but it keeps us from creating another static variable.
	 */
	if ( logsrc != none )
	{
		Syslog(LOG_INFO, "Kernel logging re-started after SIGSTOP.");
		change_state = 0;
		return;
	}

	/* Restart logging. */
	logsrc = GetKernelLogSrc();
	change_state = 0;
	return;
}


static enum LOGSRC GetKernelLogSrc(void)

{
	auto struct stat sb;


	/* Set level of kernel console messaging.. */
	if ( (ksyslog(8, NULL, console_log_level) < 0) && \
	     (errno == EINVAL) )
	{
		/*
		 * An invalid arguement error probably indicates that
		 * a pre-0.14 kernel is being run.  At this point we
		 * issue an error message and simply shut-off console
		 * logging completely.
		 */
		Syslog(LOG_WARNING, "Cannot set console log level - disabling "
			      "console output.");
		ksyslog(6, NULL, 0);
	}
	

	/*
	 * First do a stat to determine whether or not the proc based
	 * file system is available to get kernel messages from.
	 */
	if ( use_syscall ||
	    ((stat(_PATH_KLOG, &sb) < 0) && (errno == ENOENT)) )
	{
	  	/* Initialize kernel logging. */
	  	ksyslog(1, NULL, 0);
#ifdef DEBRELEASE
		Syslog(LOG_INFO, "klogd %s-%s#%s, log source = ksyslog "
		       "started.", VERSION, PATCHLEVEL, DEBRELEASE);
#else
		Syslog(LOG_INFO, "klogd %s-%s, log source = ksyslog "
		       "started.", VERSION, PATCHLEVEL);
#endif
		return(kernel);
	}

#ifndef TESTING
	if ( (kmsg = open(_PATH_KLOG, O_RDONLY)) < 0 )
	{
		fprintf(stderr, "klogd: Cannot open proc file system, " \
			"%d - %s.\n", errno, strerror(errno));
		ksyslog(7, NULL, 0);
		exit(1);
	}
#else
	kmsg = fileno(stdin);
#endif

#ifdef DEBRELEASE
	Syslog(LOG_INFO, "klogd %s-%s#%s, log source = %s started.", \
	       VERSION, PATCHLEVEL, DEBRELEASE, _PATH_KLOG);
#else
	Syslog(LOG_INFO, "klogd %s-%s, log source = %s started.", \
	       VERSION, PATCHLEVEL, _PATH_KLOG);
#endif
	return(proc);
}


extern void Syslog(int priority, char *fmt, ...)

{
	va_list ap;

	if ( debugging )
	{
		fputs("Logging line:\n", stderr);
		fprintf(stderr, "\tLine: %s\n", fmt);
		fprintf(stderr, "\tPriority: %d\n", priority);
	}

	/* Handle output to a file. */
	if ( output_file != (FILE *) 0 )
	{
		va_start(ap, fmt);
		vfprintf(output_file, fmt, ap);
		va_end(ap);
		fputc('\n', output_file);
		fflush(output_file);
		if (!one_shot)
			fsync(fileno(output_file));
		return;
	}
	
	/* Output using syslog. */
	if ( *fmt == '<' )
	{
		switch ( *(fmt+1) )
		{
		    case '0':
			priority = LOG_EMERG;
			break;
		    case '1':
			priority = LOG_ALERT;
			break;
		    case '2':
			priority = LOG_CRIT;
			break;
		    case '3':
			priority = LOG_ERR;
			break;
		    case '4':
			priority = LOG_WARNING;
			break;
		    case '5':
			priority = LOG_NOTICE;
			break;
		    case '6':
			priority = LOG_INFO;
			break;
		    case '7':
		    default:
			priority = LOG_DEBUG;
		}
		fmt += 3;
	}
	
	va_start(ap, fmt);
	vsyslog(priority, fmt, ap);
	va_end(ap);
#ifdef TESTING
	printf ("\n");
#endif

	return;
}


/*
 *     Copy characters from ptr to line until a char in the delim
 *     string is encountered or until min( space, len ) chars have
 *     been copied.
 *
 *     Returns the actual number of chars copied.
 */
static int copyin( char *line,      int space,
                   const char *ptr, int len,
                   const char *delim )
{
    auto int i;
    auto int count;

    count = len < space ? len : space;

    for(i=0; i<count && !strchr(delim, *ptr); i++ ) { *line++ = *ptr++; }

    return( i );
}

/*
 * Messages are separated by "\n".  Messages longer than
 * LOG_LINE_LENGTH are broken up.
 *
 * Kernel symbols show up in the input buffer as : "[<aaaaaa>]",
 * where "aaaaaa" is the address.  These are replaced with
 * "[symbolname+offset/size]" in the output line - symbolname,
 * offset, and size come from the kernel symbol table.
 *
 * If a kernel symbol happens to fall at the end of a message close
 * in length to LOG_LINE_LENGTH, the symbol will not be expanded.
 * (This should never happen, since the kernel should never generate
 * messages that long.
 */
static void LogLine(char *ptr, int len)
{
    enum parse_state_enum {
        PARSING_TEXT,
        PARSING_SYMSTART,      /* at < */
        PARSING_SYMBOL,        
        PARSING_SYMEND         /* at ] */
    };

    static char line_buff[LOG_LINE_LENGTH];

    static char *line                        =line_buff;
    static enum parse_state_enum parse_state = PARSING_TEXT;
    static int space                         = sizeof(line_buff)-1;

    static char *sym_start;            /* points at the '<' of a symbol */

    auto   int delta = 0;              /* number of chars copied        */

    while( len > 0 )
    {
        if( space == 0 )    /* line buffer is full */
        {
            /*
            ** Line too long.  Start a new line.
            */
            *line = 0;   /* force null terminator */

            if ( debugging )
            {
                fputs("Line buffer full:\n", stderr);
                fprintf(stderr, "\tLine: %s\n", line);
            }

            Syslog( LOG_INFO, line_buff );
            line  = line_buff;
            space = sizeof(line_buff)-1;
            parse_state = PARSING_TEXT;
        }

        switch( parse_state )
        {
        case PARSING_TEXT:
            delta = copyin( line, space, ptr, len, "\n[%" );
            line  += delta;
            ptr   += delta;
            space -= delta;
            len   -= delta;

            if( space == 0 || len == 0 )
            {
                break;  /* full line_buff or end of input buffer */
            }

            if( *ptr == '\n' )  /* newline */
            {
                *line++ = *ptr++;  /* copy it in */
                space -= 1;
                len   -= 1;

                *line = 0;  /* force null terminator */
                Syslog( LOG_INFO, line_buff );
                line  = line_buff;
                space = sizeof(line_buff)-1;
                break;
            }
            if( *ptr == '[' )   /* possible kernel symbol */
            {
                *line++ = *ptr++;
                space -= 1;
                len   -= 1;
                parse_state = PARSING_SYMSTART;      /* at < */
                break;
            }
            if( *ptr == '%' )   /* dangerous printf marker */
            {
                delta = 0;
                while (len && *ptr == '%')
                {
                    *line++ = *ptr++;	/* copy it in */
                    space -= 1;
                    len   -= 1;
                    delta++;
                }
                if (delta % 2)	/* odd amount of %'s */
                {
                    if (space)
                    {
                        *line++ = '%';	/* so simply add one */
                        space -= 1;
                    }
                    else 
                    {
                        *line++ = '\0';	/* remove the last one / terminate the string */
                    }

                }
            }
            break;

        case PARSING_SYMSTART:
               if( *ptr != '<' )
               {
                  parse_state = PARSING_TEXT;        /* not a symbol */
                  break;
               }

               /*
               ** Save this character for now.  If this turns out to
               ** be a valid symbol, this char will be replaced later.
               ** If not, we'll just leave it there.
               */

               sym_start = line; /* this will point at the '<' */

               *line++ = *ptr++;
               space -= 1;
               len   -= 1;
               parse_state = PARSING_SYMBOL;     /* symbol... */
               break;

        case PARSING_SYMBOL:
               delta = copyin( line, space, ptr, len, ">\n[" );
               line  += delta;
               ptr   += delta;
               space -= delta;
               len   -= delta;
               if( space == 0 || len == 0 )
               {
                  break;  /* full line_buff or end of input buffer */
               }
               if( *ptr != '>' )
               {
                  parse_state = PARSING_TEXT;
                  break;
               }

               *line++ = *ptr++;  /* copy the '>' */
               space -= 1;
               len   -= 1;

               parse_state = PARSING_SYMEND;

               break;

        case PARSING_SYMEND:
               if( *ptr != ']' )
               {
                  parse_state = PARSING_TEXT;        /* not a symbol */
                  break;
               }

               /*
               ** It's really a symbol!  Replace address with the
               ** symbol text.
               */
               {
                   auto int sym_space;

                   unsigned long value;
                   auto struct symbol sym;
                   auto char *symbol;

                   *(line-1) = 0;    /* null terminate the address string */
                   value  = strtoul(sym_start+1, (char **) 0, 16);
                   *(line-1) = '>';  /* put back delim */
                   /* JW: Modified to eliminate ksym.c LookupSymbol() dep */
                   symbol = "symbolfoo";
                   if ( !symbol_lookup || symbol == (char *) 0 )
                   {
                       parse_state = PARSING_TEXT;
                       break;
                   }

                   /*
                    ** verify there is room in the line buffer
                    */
                   sym_space = space + ( line - sym_start );
                   if( sym_space < strlen(symbol) + 30 ) /*(30 should be overkill)*/
                   {
                       parse_state = PARSING_TEXT;  /* not enough space */
                       break;
                   }

                   delta = sprintf( sym_start, "%s+%d/%d]",
                           symbol, sym.offset, sym.size );

                   space = sym_space + delta;
                   line  = sym_start + delta;
               }
               ptr++;
               len--;
               parse_state = PARSING_TEXT;
               break;

        default: /* Can't get here! */
               parse_state = PARSING_TEXT;

        }
    }

    return;
}

int main(int argc, char **argv)
{
    char msg[LOG_LINE_LENGTH] = "Format string test: [<%x %x %x %x>]\n";
    int msglen = strlen(msg);

    printf("Calling LogLine with string \"%s\".\n", msg);
    LogLine(msg, msglen);
    printf("Done.\n");

    return 0;
}
