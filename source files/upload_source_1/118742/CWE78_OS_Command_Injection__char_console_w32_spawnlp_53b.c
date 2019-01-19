/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_console_w32_spawnlp_53b.c
Label Definition File: CWE78_OS_Command_Injection.strings.label.xml
Template File: sources-sink-53b.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: console Read input from the console
 * GoodSource: Fixed string
 * Sink: w32_spawnlp
 *    BadSink : execute command with spawnlp
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

#include <process.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE78_OS_Command_Injection__char_console_w32_spawnlp_53c_badSink(char * data);

void CWE78_OS_Command_Injection__char_console_w32_spawnlp_53b_badSink(char * data)
{
    CWE78_OS_Command_Injection__char_console_w32_spawnlp_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE78_OS_Command_Injection__char_console_w32_spawnlp_53c_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE78_OS_Command_Injection__char_console_w32_spawnlp_53b_goodG2BSink(char * data)
{
    CWE78_OS_Command_Injection__char_console_w32_spawnlp_53c_goodG2BSink(data);
}

#endif /* OMITGOOD */
