/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_dest_wchar_t_cpy_84_goodG2B.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_dest.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using new[] and set data pointer to a small buffer
 * GoodSource: Allocate using new[] and set data pointer to a large buffer
 * Sinks: cpy
 *    BadSink : Copy string to data using wcscpy
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_dest_wchar_t_cpy_84.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_dest_wchar_t_cpy_84
{
CWE122_Heap_Based_Buffer_Overflow__cpp_dest_wchar_t_cpy_84_goodG2B::CWE122_Heap_Based_Buffer_Overflow__cpp_dest_wchar_t_cpy_84_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Allocate using new[] and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = new wchar_t[100];
    data[0] = L'\0'; /* null terminate */
}

CWE122_Heap_Based_Buffer_Overflow__cpp_dest_wchar_t_cpy_84_goodG2B::~CWE122_Heap_Based_Buffer_Overflow__cpp_dest_wchar_t_cpy_84_goodG2B()
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        wcscpy(data, source);
        printWLine(data);
        delete [] data;
    }
}
}
#endif /* OMITGOOD */
