/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_loop_42.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.label.xml
Template File: sources-sink-42.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sink: loop
 *    BadSink : Copy int array to data using a loop
 * Flow Variant: 42 Data flow: data returned from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

static int * badSource(int * data)
{
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (int *)malloc(50*sizeof(int));
    return data;
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_loop_42_bad()
{
    int * data;
    data = NULL;
    data = badSource(data);
    {
        int source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printIntLine(data[0]);
            free(data);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

static int * goodG2BSource(int * data)
{
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (int *)malloc(100*sizeof(int));
    return data;
}

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    int * data;
    data = NULL;
    data = goodG2BSource(data);
    {
        int source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printIntLine(data[0]);
            free(data);
        }
    }
}

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_loop_42_good()
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
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_loop_42_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_loop_42_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
