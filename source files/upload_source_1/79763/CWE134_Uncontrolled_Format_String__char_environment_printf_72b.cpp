/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_environment_printf_72b.cpp
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-72b.tmpl.cpp
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: environment Read input from an environment variable
 * GoodSource: Copy a fixed string into data
 * Sinks: printf
 *    GoodSink: printf with "%s" as the first argument and data as the second
 *    BadSink : printf with only data as an argument
 * Flow Variant: 72 Data flow: data passed in a vector from one function to another in different source files
 *
 * */

#include "std_testcase.h"
#include <vector>

#ifndef _WIN32
#include <wchar.h>
#endif

using namespace std;

namespace CWE134_Uncontrolled_Format_String__char_environment_printf_72
{

#ifndef OMITBAD

void badSink(vector<char *> dataVector)
{
    /* copy data out of dataVector */
    char * data = dataVector[2];
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    printf(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(vector<char *> dataVector)
{
    char * data = dataVector[2];
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    printf(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink(vector<char *> dataVector)
{
    char * data = dataVector[2];
    /* FIX: Specify the format disallowing a format string vulnerability */
    printf("%s\n", data);
}

#endif /* OMITGOOD */

} /* close namespace */
