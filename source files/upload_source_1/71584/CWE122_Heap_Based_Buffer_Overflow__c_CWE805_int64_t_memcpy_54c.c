/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_54c.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.label.xml
Template File: sources-sink-54c.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sink: memcpy
 *    BadSink : Copy int64_t array to data using memcpy
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_54d_badSink(int64_t * data);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_54c_badSink(int64_t * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_54d_goodG2BSink(int64_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_54c_goodG2BSink(int64_t * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_54d_goodG2BSink(data);
}

#endif /* OMITGOOD */
