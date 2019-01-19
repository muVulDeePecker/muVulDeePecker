/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_wchar_t_environment_22b.c
Label Definition File: CWE114_Process_Control__w32.label.xml
Template File: sources-sink-22b.tmpl.c
*/
/*
 * @description
 * CWE: 114 Process Control
 * BadSource: environment Read input from an environment variable
 * GoodSource: Hard code the full pathname to the library
 * Sink:
 *    BadSink : Load a dynamic link library
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define ENV_VARIABLE L"ADD"

#ifdef _WIN32
#define GETENV _wgetenv
#else
#define GETENV getenv
#endif

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
extern int CWE114_Process_Control__w32_wchar_t_environment_22_badGlobal;

wchar_t * CWE114_Process_Control__w32_wchar_t_environment_22_badSource(wchar_t * data)
{
    if(CWE114_Process_Control__w32_wchar_t_environment_22_badGlobal)
    {
        {
            /* Append input from an environment variable to data */
            size_t dataLen = wcslen(data);
            wchar_t * environment = GETENV(ENV_VARIABLE);
            /* If there is data in the environment variable */
            if (environment != NULL)
            {
                /* POTENTIAL FLAW: Read data from an environment variable */
                wcsncat(data+dataLen, environment, 100-dataLen-1);
            }
        }
    }
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
extern int CWE114_Process_Control__w32_wchar_t_environment_22_goodG2B1Global;
extern int CWE114_Process_Control__w32_wchar_t_environment_22_goodG2B2Global;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
wchar_t * CWE114_Process_Control__w32_wchar_t_environment_22_goodG2B1Source(wchar_t * data)
{
    if(CWE114_Process_Control__w32_wchar_t_environment_22_goodG2B1Global)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Specify the full pathname for the library */
        wcscpy(data, L"C:\\Windows\\System32\\winsrv.dll");
    }
    return data;
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
wchar_t * CWE114_Process_Control__w32_wchar_t_environment_22_goodG2B2Source(wchar_t * data)
{
    if(CWE114_Process_Control__w32_wchar_t_environment_22_goodG2B2Global)
    {
        /* FIX: Specify the full pathname for the library */
        wcscpy(data, L"C:\\Windows\\System32\\winsrv.dll");
    }
    return data;
}

#endif /* OMITGOOD */
