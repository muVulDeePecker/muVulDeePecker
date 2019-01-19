/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE690_NULL_Deref_From_Return__wchar_t_calloc_61a.c
Label Definition File: CWE690_NULL_Deref_From_Return.free.label.xml
Template File: source-sinks-61a.tmpl.c
*/
/*
 * @description
 * CWE: 690 Unchecked Return Value To NULL Pointer
 * BadSource: calloc Allocate data using calloc()
 * Sinks:
 *    GoodSink: Check to see if the data allocation failed and if not, use data
 *    BadSink : Don't check for NULL and use data
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
wchar_t * CWE690_NULL_Deref_From_Return__wchar_t_calloc_61b_badSource(wchar_t * data);

void CWE690_NULL_Deref_From_Return__wchar_t_calloc_61_bad()
{
    wchar_t * data;
    data = NULL; /* Initialize data */
    data = CWE690_NULL_Deref_From_Return__wchar_t_calloc_61b_badSource(data);
    /* FLAW: Initialize memory buffer without checking to see if the memory allocation function failed */
    wcscpy(data, L"Initialize");
    printWLine(data);
    free(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
wchar_t * CWE690_NULL_Deref_From_Return__wchar_t_calloc_61b_goodB2GSource(wchar_t * data);

static void goodB2G()
{
    wchar_t * data;
    data = NULL; /* Initialize data */
    data = CWE690_NULL_Deref_From_Return__wchar_t_calloc_61b_goodB2GSource(data);
    /* FIX: Check to see if the memory allocation function was successful before initializing the memory buffer */
    if (data != NULL)
    {
        wcscpy(data, L"Initialize");
        printWLine(data);
        free(data);
    }
}

void CWE690_NULL_Deref_From_Return__wchar_t_calloc_61_good()
{
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE690_NULL_Deref_From_Return__wchar_t_calloc_61_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE690_NULL_Deref_From_Return__wchar_t_calloc_61_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
