/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__new_wchar_t_memmove_64a.cpp
Label Definition File: CWE126_Buffer_Overread__new.label.xml
Template File: sources-sink-64a.tmpl.cpp
*/
/*
 * @description
 * CWE: 126 Buffer Over-read
 * BadSource:  Use a small buffer
 * GoodSource: Use a large buffer
 * Sinks: memmove
 *    BadSink : Copy data to string using memmove
 * Flow Variant: 64 Data flow: void pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE126_Buffer_Overread__new_wchar_t_memmove_64
{

#ifndef OMITBAD

/* bad function declaration */
void badSink(void * dataVoidPtr);

void bad()
{
    wchar_t * data;
    data = NULL;
    /* FLAW: Use a small buffer */
    data = new wchar_t[50];
    wmemset(data, L'A', 50-1); /* fill with 'A's */
    data[50-1] = L'\0'; /* null terminate */
    badSink(&data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(void * dataVoidPtr);

static void goodG2B()
{
    wchar_t * data;
    data = NULL;
    /* FIX: Use a large buffer */
    data = new wchar_t[100];
    wmemset(data, L'A', 100-1); /* fill with 'A's */
    data[100-1] = L'\0'; /* null terminate */
    goodG2BSink(&data);
}

void good()
{
    goodG2B();
}

#endif /* OMITGOOD */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

using namespace CWE126_Buffer_Overread__new_wchar_t_memmove_64; /* so that we can use good and bad easily */

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
