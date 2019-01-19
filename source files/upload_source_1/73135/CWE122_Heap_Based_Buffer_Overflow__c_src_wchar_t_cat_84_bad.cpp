/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_src_wchar_t_cat_84_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_src.label.xml
Template File: sources-sink-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sinks: cat
 *    BadSink : Copy data to string using wcscat
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__c_src_wchar_t_cat_84.h"

namespace CWE122_Heap_Based_Buffer_Overflow__c_src_wchar_t_cat_84
{
CWE122_Heap_Based_Buffer_Overflow__c_src_wchar_t_cat_84_bad::CWE122_Heap_Based_Buffer_Overflow__c_src_wchar_t_cat_84_bad(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    wmemset(data, L'A', 100-1); /* fill with L'A's */
    data[100-1] = L'\0'; /* null terminate */
}

CWE122_Heap_Based_Buffer_Overflow__c_src_wchar_t_cat_84_bad::~CWE122_Heap_Based_Buffer_Overflow__c_src_wchar_t_cat_84_bad()
{
    {
        wchar_t dest[50] = L"";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-wcslen(dest)*/
        wcscat(dest, data);
        printWLine(data);
        free(data);
    }
}
}
#endif /* OMITBAD */
