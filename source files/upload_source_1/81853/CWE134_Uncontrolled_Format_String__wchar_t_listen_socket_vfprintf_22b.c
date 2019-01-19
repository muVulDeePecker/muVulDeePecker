/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22b.c
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-22b.tmpl.c
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Copy a fixed string into data
 * Sinks: vfprintf
 *    GoodSink: vfwprintf with a format string
 *    BadSink : vfwprintf without a format string
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include <stdarg.h>
#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the sink function */
extern int CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_badGlobal;

void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_badVaSink(wchar_t * data, ...)
{
    if(CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_badGlobal)
    {
        {
            va_list args;
            va_start(args, data);
            /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
            vfwprintf(stdout, data, args);
            va_end(args);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the sink functions. */
extern int CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodB2G1Global;
extern int CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodB2G2Global;
extern int CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodG2BGlobal;

/* goodB2G1() - use badsource and goodsink by setting the static variable to false instead of true */
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodB2G1_vasink(wchar_t * data, ...)
{
    if(CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodB2G1Global)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            va_list args;
            va_start(args, data);
            /* FIX: Specify the format disallowing a format string vulnerability */
            vfwprintf(stdout, L"%s", args);
            va_end(args);
        }
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the if in the sink function */
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodB2G2_vasink(wchar_t * data, ...)
{
    if(CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodB2G2Global)
    {
        {
            va_list args;
            va_start(args, data);
            /* FIX: Specify the format disallowing a format string vulnerability */
            vfwprintf(stdout, L"%s", args);
            va_end(args);
        }
    }
}

/* goodG2B() - use goodsource and badsink */
void CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodG2BVaSink(wchar_t * data, ...)
{
    if(CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vfprintf_22_goodG2BGlobal)
    {
        {
            va_list args;
            va_start(args, data);
            /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
            vfwprintf(stdout, data, args);
            va_end(args);
        }
    }
}

#endif /* OMITGOOD */
