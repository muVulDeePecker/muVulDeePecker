/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_61b.c
Label Definition File: CWE680_Integer_Overflow_to_Buffer_Overflow__malloc.label.xml
Template File: sources-sink-61b.tmpl.c
*/
/*
 * @description
 * CWE: 680 Integer Overflow to Buffer Overflow
 * BadSource: fixed Fixed value that will cause an integer overflow in the sink
 * GoodSource: Small number greater than zero that will not cause an integer overflow in the sink
 * Sinks:
 *    BadSink : Attempt to allocate array using length value from source
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

int CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_61b_badSource(int data)
{
    /* FLAW: Set data to a value that will cause an integer overflow in the call to malloc() in the sink */
    data = INT_MAX / 2 + 2; /* 1073741825 */
    /* NOTE: This value will cause the sink to only allocate 4 bytes of memory, however
     * the for loop will attempt to access indices 0-1073741824 */
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
int CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_61b_goodG2BSource(int data)
{
    /* FIX: Set data to a relatively small number greater than zero */
    data = 20;
    return data;
}

#endif /* OMITGOOD */
