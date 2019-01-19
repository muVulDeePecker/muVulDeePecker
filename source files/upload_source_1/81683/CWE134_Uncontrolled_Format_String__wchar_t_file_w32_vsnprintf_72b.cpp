/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__wchar_t_file_w32_vsnprintf_72b.cpp
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-72b.tmpl.cpp
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: w32_vsnprintf
 *    GoodSink: _vsnwprintf with a format string
 *    BadSink : _vsnwprintf without a format string
 * Flow Variant: 72 Data flow: data passed in a vector from one function to another in different source files
 *
 * */
#include <stdarg.h>
#include <vector>
#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

using namespace std;

namespace CWE134_Uncontrolled_Format_String__wchar_t_file_w32_vsnprintf_72
{

#ifndef OMITBAD

static void badVaSink(wchar_t * data, ...)
{
    {
        wchar_t dest[100] = L"";
        va_list args;
        va_start(args, data);
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        _vsnwprintf(dest, 100-1, data, args);
        va_end(args);
        printWLine(dest);
    }
}

void badSink(vector<wchar_t *> dataVector)
{
    /* copy data out of dataVector */
    wchar_t * data = dataVector[2];
    badVaSink(data, data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2BVaSink(wchar_t * data, ...)
{
    {
        wchar_t dest[100] = L"";
        va_list args;
        va_start(args, data);
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        _vsnwprintf(dest, 100-1, data, args);
        va_end(args);
        printWLine(dest);
    }
}

void goodG2BSink(vector<wchar_t *> dataVector)
{
    wchar_t * data = dataVector[2];
    goodG2BVaSink(data, data);
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2GVaSink(wchar_t * data, ...)
{
    {
        wchar_t dest[100] = L"";
        va_list args;
        va_start(args, data);
        /* FIX: Specify the format disallowing a format string vulnerability */
        _vsnwprintf(dest, 100-1, L"%s", args);
        va_end(args);
        printWLine(dest);
    }
}

void goodB2GSink(vector<wchar_t *> dataVector)
{
    wchar_t * data = dataVector[2];
    goodB2GVaSink(data, data);
}

#endif /* OMITGOOD */

} /* close namespace */
