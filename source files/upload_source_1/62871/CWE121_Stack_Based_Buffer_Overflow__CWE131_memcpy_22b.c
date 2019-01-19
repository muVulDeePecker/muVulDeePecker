/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE131.label.xml
Template File: sources-sink-22b.tmpl.c
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
extern int CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_badGlobal;

int * CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_badSource(int * data)
{
    if(CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_badGlobal)
    {
        /* FLAW: Allocate memory without using sizeof(int) */
        data = (int *)ALLOCA(10);
    }
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the source functions. */
extern int CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B1Global;
extern int CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B2Global;

/* goodG2B1() - use goodsource and badsink by setting the static variable to false instead of true */
int * CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B1Source(int * data)
{
    if(CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B1Global)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Allocate memory using sizeof(int) */
        data = (int *)ALLOCA(10*sizeof(int));
    }
    return data;
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the if in the source function */
int * CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B2Source(int * data)
{
    if(CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_22_goodG2B2Global)
    {
        /* FIX: Allocate memory using sizeof(int) */
        data = (int *)ALLOCA(10*sizeof(int));
    }
    return data;
}

#endif /* OMITGOOD */
