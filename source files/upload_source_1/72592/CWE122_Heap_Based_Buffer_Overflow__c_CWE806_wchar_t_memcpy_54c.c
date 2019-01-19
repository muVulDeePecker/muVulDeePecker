/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_54c.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE806.label.xml
Template File: sources-sink-54c.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sink: memcpy
 *    BadSink : Copy data to string using memcpy
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_54d_badSink(wchar_t * data);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_54c_badSink(wchar_t * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_54d_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_54c_goodG2BSink(wchar_t * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_54d_goodG2BSink(data);
}

#endif /* OMITGOOD */
