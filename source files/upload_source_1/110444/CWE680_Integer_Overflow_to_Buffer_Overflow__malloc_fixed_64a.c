/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64a.c
Label Definition File: CWE680_Integer_Overflow_to_Buffer_Overflow__malloc.label.xml
Template File: sources-sink-64a.tmpl.c
*/
/*
 * @description
 * CWE: 680 Integer Overflow to Buffer Overflow
 * BadSource: fixed Fixed value that will cause an integer overflow in the sink
 * GoodSource: Small number greater than zero that will not cause an integer overflow in the sink
 * Sinks:
 *    BadSink : Attempt to allocate array using length value from source
 * Flow Variant: 64 Data flow: void pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

/* bad function declaration */
void CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64b_badSink(void * dataVoidPtr);

void CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64_bad()
{
    int data;
    /* Initialize data */
    data = -1;
    /* FLAW: Set data to a value that will cause an integer overflow in the call to malloc() in the sink */
    data = INT_MAX / 2 + 2; /* 1073741825 */
    /* NOTE: This value will cause the sink to only allocate 4 bytes of memory, however
     * the for loop will attempt to access indices 0-1073741824 */
    CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64b_badSink(&data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64b_goodG2BSink(void * dataVoidPtr);

static void goodG2B()
{
    int data;
    /* Initialize data */
    data = -1;
    /* FIX: Set data to a relatively small number greater than zero */
    data = 20;
    CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64b_goodG2BSink(&data);
}

void CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_64_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
