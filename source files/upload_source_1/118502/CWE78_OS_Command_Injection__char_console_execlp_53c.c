/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_console_execlp_53c.c
Label Definition File: CWE78_OS_Command_Injection.strings.label.xml
Template File: sources-sink-53c.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: console Read input from the console
 * GoodSource: Fixed string
 * Sink: execlp
 *    BadSink : execute command with execlp
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define COMMAND_INT_PATH "%WINDIR%\\system32\\cmd.exe"
#define COMMAND_INT "cmd.exe"
#define COMMAND_ARG1 "/c"
#define COMMAND_ARG2 "dir"
#define COMMAND_ARG3 data
#else /* NOT _WIN32 */
#include <unistd.h>
#define COMMAND_INT_PATH "/bin/sh"
#define COMMAND_INT "sh"
#define COMMAND_ARG1 "ls"
#define COMMAND_ARG2 "-la"
#define COMMAND_ARG3 data
#endif

#ifdef _WIN32
#include <process.h>
#define EXECLP _execlp
#else /* NOT _WIN32 */
#define EXECLP execlp
#endif

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE78_OS_Command_Injection__char_console_execlp_53d_badSink(char * data);

void CWE78_OS_Command_Injection__char_console_execlp_53c_badSink(char * data)
{
    CWE78_OS_Command_Injection__char_console_execlp_53d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE78_OS_Command_Injection__char_console_execlp_53d_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE78_OS_Command_Injection__char_console_execlp_53c_goodG2BSink(char * data)
{
    CWE78_OS_Command_Injection__char_console_execlp_53d_goodG2BSink(data);
}

#endif /* OMITGOOD */
