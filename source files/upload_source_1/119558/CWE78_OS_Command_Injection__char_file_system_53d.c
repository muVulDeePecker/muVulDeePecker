/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_file_system_53d.c
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-53d.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: file Read input from a file
 * GoodSource: Fixed string
 * Sink: system
 *    BadSink : Execute command in data using system()
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define FULL_COMMAND "%WINDIR%\\system32\\cmd.exe /c dir "
#else
#include <unistd.h>
#define FULL_COMMAND "/bin/sh ls -la "
#endif

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"
#else
#define FILENAME "/tmp/file.txt"
#endif

#ifdef _WIN32
#define SYSTEM system
#else /* NOT _WIN32 */
#define SYSTEM system
#endif

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

void CWE78_OS_Command_Injection__char_file_system_53d_badSink(char * data)
{
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE78_OS_Command_Injection__char_file_system_53d_goodG2BSink(char * data)
{
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}

#endif /* OMITGOOD */
