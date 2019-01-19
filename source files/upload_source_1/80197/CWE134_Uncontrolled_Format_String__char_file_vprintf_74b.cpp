/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_file_vprintf_74b.cpp
Label Definition File: CWE134_Uncontrolled_Format_String.vasinks.label.xml
Template File: sources-vasinks-74b.tmpl.cpp
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: file Read input from a file
 * GoodSource: Copy a fixed string into data
 * Sinks: vprintf
 *    GoodSink: vprintf with a format string
 *    BadSink : vprintf without a format string
 * Flow Variant: 74 Data flow: data passed in a map from one function to another in different source files
 *
 * */
#include <stdarg.h>
#include <map>
#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

using namespace std;

namespace CWE134_Uncontrolled_Format_String__char_file_vprintf_74
{

#ifndef OMITBAD

static void badVaSink(char * data, ...)
{
    {
        va_list args;
        va_start(args, data);
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        vprintf(data, args);
        va_end(args);
    }
}

void badSink(map<int, char *> dataMap)
{
    /* copy data out of dataMap */
    char * data = dataMap[2];
    badVaSink(data, data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2BVaSink(char * data, ...)
{
    {
        va_list args;
        va_start(args, data);
        /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
        vprintf(data, args);
        va_end(args);
    }
}

void goodG2BSink(map<int, char *> dataMap)
{
    char * data = dataMap[2];
    goodG2BVaSink(data, data);
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2GVaSink(char * data, ...)
{
    {
        va_list args;
        va_start(args, data);
        /* FIX: Specify the format disallowing a format string vulnerability */
        vprintf("%s", args);
        va_end(args);
    }
}

void goodB2GSink(map<int, char *> dataMap)
{
    char * data = dataMap[2];
    goodB2GVaSink(data, data);
}

#endif /* OMITGOOD */

} /* close namespace */
