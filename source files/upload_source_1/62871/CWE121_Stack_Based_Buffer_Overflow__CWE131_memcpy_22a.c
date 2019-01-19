/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22a.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE131.label.xml
Template File: sources-sink-22a.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Allocate memory without using sizeof(int)
 * GoodSource: Allocate memory using sizeof(int)
 * Sink: memcpy
 *    BadSink : Copy array to data using memcpy()
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

/* The global variable below is used to drive control flow in the source function */
int CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_badGlobal = 0;

int * CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_badSource(int * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_bad()
{
    int * data;
    data = NULL;
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_badGlobal = 1; /* true */
    data = CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_badSource(data);
    {
        int source[10] = {0};
        /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
        memcpy(data, source, 10*sizeof(int));
        printIntLine(data[0]);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
int CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B1Global = 0;
int CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B2Global = 0;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
int * CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B1Source(int * data);

static void goodG2B1()
{
    int * data;
    data = NULL;
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B1Global = 0; /* false */
    data = CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B1Source(data);
    {
        int source[10] = {0};
        /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
        memcpy(data, source, 10*sizeof(int));
        printIntLine(data[0]);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
int * CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B2Source(int * data);

static void goodG2B2()
{
    int * data;
    data = NULL;
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B2Global = 1; /* true */
    data = CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B2Source(data);
    {
        int source[10] = {0};
        /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
        memcpy(data, source, 10*sizeof(int));
        printIntLine(data[0]);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_good()
{
    goodG2B1();
    goodG2B2();
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
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
