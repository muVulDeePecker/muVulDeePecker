/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_file_system_54d.c
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-54d.tmpl.c
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: file Read input from a file
 * GoodSource: Fixed string
 * Sink: system
 *    BadSink : Execute command in data using system()
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
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

/* bad function declaration */
void CWE78_OS_Command_Injection__char_file_system_54e_badSink(char * data);

void CWE78_OS_Command_Injection__char_file_system_54d_badSink(char * data)
{
    CWE78_OS_Command_Injection__char_file_system_54e_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE78_OS_Command_Injection__char_file_system_54e_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE78_OS_Command_Injection__char_file_system_54d_goodG2BSink(char * data)
{
    CWE78_OS_Command_Injection__char_file_system_54e_goodG2BSink(data);
}

#endif /* OMITGOOD */
