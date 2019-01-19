/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_84_goodG2B.cpp
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: vfprintf
 *    GoodSink: vfwprintf with a format string
 *    BadSink : vfwprintf without a format string
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include <stdarg.h>
#include "std_testcase.h"
#include "CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_84.h"

namespace CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_84
{
CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_84_goodG2B::CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_84_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Use a fixed string that does not contain a format specifier */
    wcscpy(data, L"fixedstringtest");
}

static void goodG2BVaSink(wchar_t * data, ...)
{
    {
        va_list args;
        va_start(args, data);
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        vfwprintf(stdout, data, args);
        va_end(args);
    }
}

CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_84_goodG2B::~CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_84_goodG2B()
{
    goodG2BVaSink(data, data);
}
}
#endif /* OMITGOOD */
