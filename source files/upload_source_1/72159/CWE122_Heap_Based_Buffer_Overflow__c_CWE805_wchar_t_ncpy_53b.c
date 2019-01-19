/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncpy_53b.c
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-53b.tmpl.c
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sink: ncpy
 *    BadSink : Copy string to data using wcsncpy
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncpy_53c_badSink(wchar_t * data);

void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncpy_53b_badSink(wchar_t * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncpy_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncpy_53c_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncpy_53b_goodG2BSink(wchar_t * data)
{
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncpy_53c_goodG2BSink(data);
}

#endif /* OMITGOOD */
