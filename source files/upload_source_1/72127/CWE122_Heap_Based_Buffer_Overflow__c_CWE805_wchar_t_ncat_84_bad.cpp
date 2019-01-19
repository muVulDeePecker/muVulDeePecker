/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncat_84_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.string.label.xml
Template File: sources-sink-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: ncat
 *    BadSink : Copy string to data using wcsncat
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncat_84.h"

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncat_84
{
CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncat_84_bad::CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncat_84_bad(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (wchar_t *)malloc(50*sizeof(wchar_t));
    data[0] = L'\0'; /* null terminate */
}

CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncat_84_bad::~CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_ncat_84_bad()
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than sizeof(data)-strlen(data) */
        wcsncat(data, source, 100);
        printWLine(data);
        free(data);
    }
}
}
#endif /* OMITBAD */
