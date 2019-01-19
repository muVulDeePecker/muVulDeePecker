/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_console_popen_63b.c
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-63b.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: console Read input from the console
 * GoodSource: Fixed string
 * Sinks: popen
 *    BadSink : Execute command in data using popen()
 * Flow Variant: 63 Data flow: pointer to data passed from one function to another in different source files
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

/* define POPEN as _popen on Windows and popen otherwise */
#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#else /* NOT _WIN32 */
#define POPEN popen
#define PCLOSE pclose
#endif

#ifndef OMITBAD

void CWE78_OS_Command_Injection__char_console_popen_63b_badSink(char * * dataPtr)
{
    char * data = *dataPtr;
    {
        FILE *pipe;
        /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
        pipe = POPEN(data, "wb");
        if (pipe != NULL)
        {
            PCLOSE(pipe);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE78_OS_Command_Injection__char_console_popen_63b_goodG2BSink(char * * dataPtr)
{
    char * data = *dataPtr;
    {
        FILE *pipe;
        /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
        pipe = POPEN(data, "wb");
        if (pipe != NULL)
        {
            PCLOSE(pipe);
        }
    }
}

#endif /* OMITGOOD */
