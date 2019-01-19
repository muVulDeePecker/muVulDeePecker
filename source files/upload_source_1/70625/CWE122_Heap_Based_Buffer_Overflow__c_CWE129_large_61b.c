/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_61b.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE129.label.xml
Template File: sources-sinks-61b.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource: large Large index value that is greater than 10-1
 * GoodSource: Larger than zero but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

int CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_61b_badSource(int data)
{
    /* POTENTIAL FLAW: Use an invalid index */
    data = 10;
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
int CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_61b_goodG2BSource(int data)
{
    /* FIX: Use a value greater than 0, but less than 10 to avoid attempting to
    * access an index of the array in the sink that is out-of-bounds */
    data = 7;
    return data;
}

/* goodB2G() uses the BadSource with the GoodSink */
int CWE122_Heap_Based_Buffer_Overflow__c_CWE129_large_61b_goodB2GSource(int data)
{
    /* POTENTIAL FLAW: Use an invalid index */
    data = 10;
    return data;
}

#endif /* OMITGOOD */
