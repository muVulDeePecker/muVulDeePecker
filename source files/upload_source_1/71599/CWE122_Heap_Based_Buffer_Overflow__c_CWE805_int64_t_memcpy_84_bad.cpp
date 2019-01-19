/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_84_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.label.xml
Template File: sources-sink-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: memcpy
 *    BadSink : Copy int64_t array to data using memcpy
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_84.h"

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_84
{
CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_84_bad::CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_84_bad(int64_t * dataCopy)
{
    data = dataCopy;
    /* FLAW: Allocate and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = (int64_t *)malloc(50*sizeof(int64_t));
}

CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_84_bad::~CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int64_t_memcpy_84_bad()
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memcpy(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
        free(data);
    }
}
}
#endif /* OMITBAD */
