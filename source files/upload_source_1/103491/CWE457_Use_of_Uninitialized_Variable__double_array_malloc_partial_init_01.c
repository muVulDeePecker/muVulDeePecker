/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__double_array_malloc_partial_init_01.c
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c_array.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: partial_init Initialize part, but not all of the array
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE457_Use_of_Uninitialized_Variable__double_array_malloc_partial_init_01_bad()
{
    double * data;
    data = (double *)malloc(10*sizeof(double));
    /* POTENTIAL FLAW: Partially initialize data */
    {
        int i;
        for(i=0; i<(10/2); i++)
        {
            data[i] = (double)i;
        }
    }
    /* POTENTIAL FLAW: Use data without initializing it */
    {
        int i;
        for(i=0; i<10; i++)
        {
            printDoubleLine(data[i]);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    double * data;
    data = (double *)malloc(10*sizeof(double));
    /* FIX: Completely initialize data */
    {
        int i;
        for(i=0; i<10; i++)
        {
            data[i] = (double)i;
        }
    }
    /* POTENTIAL FLAW: Use data without initializing it */
    {
        int i;
        for(i=0; i<10; i++)
        {
            printDoubleLine(data[i]);
        }
    }
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    double * data;
    data = (double *)malloc(10*sizeof(double));
    /* POTENTIAL FLAW: Partially initialize data */
    {
        int i;
        for(i=0; i<(10/2); i++)
        {
            data[i] = (double)i;
        }
    }
    /* FIX: Ensure data is initialized before use */
    {
        int i;
        for(i=0; i<10; i++)
        {
            data[i] = (double)i;
        }
    }
    {
        int i;
        for(i=0; i<10; i++)
        {
            printDoubleLine(data[i]);
        }
    }
}

void CWE457_Use_of_Uninitialized_Variable__double_array_malloc_partial_init_01_good()
{
    goodG2B();
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
    CWE457_Use_of_Uninitialized_Variable__double_array_malloc_partial_init_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE457_Use_of_Uninitialized_Variable__double_array_malloc_partial_init_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
