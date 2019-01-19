/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE426_Untrusted_Search_Path__wchar_t_system_53b.c
Label Definition File: CWE426_Untrusted_Search_Path.label.xml
Template File: sources-sink-53b.tmpl.c
*/
/*
 * @description
 * CWE: 426 Untrusted Search Path
 * BadSource:  Don't specify the full path in the OS command
 * GoodSource: Specify the full path in the OS command
 * Sink: system
 *    BadSink : Execute the _wsystem function
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#ifdef _WIN32
#define BAD_OS_COMMAND L"cmd.exe /c dir"

/* REVIEWERS NOTE:
 * This hard-coded path is probably incorrect for Windows systems, as it will
 * function improperly on 9x/NT/2K, possibly on XP+ systems upgraded from 2K,
 * and could introduce code execution vulnerabilities on Windows systems that
 * have a system drive on an alternate drive letter (e.g., d:\windows)
 */
#define GOOD_OS_COMMAND L"c:\\windows\\system32\\cmd.exe /c dir"
#else /* NOT _WIN32 */
#define BAD_OS_COMMAND L"ls -la"
#define GOOD_OS_COMMAND L"/usr/bin/ls -la"
#endif /* end NOT _WIN32 */

#ifdef _WIN32
#define SYSTEM _wsystem
#else /* NOT _WIN32 */
#define SYSTEM system
#endif

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE426_Untrusted_Search_Path__wchar_t_system_53c_badSink(wchar_t * data);

void CWE426_Untrusted_Search_Path__wchar_t_system_53b_badSink(wchar_t * data)
{
    CWE426_Untrusted_Search_Path__wchar_t_system_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE426_Untrusted_Search_Path__wchar_t_system_53c_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE426_Untrusted_Search_Path__wchar_t_system_53b_goodG2BSink(wchar_t * data)
{
    CWE426_Untrusted_Search_Path__wchar_t_system_53c_goodG2BSink(data);
}

#endif /* OMITGOOD */
