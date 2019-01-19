/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_src_wchar_t_cpy_84_goodG2B.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_src.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sinks: cpy
 *    BadSink : Copy data to string using wcscpy
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_src_wchar_t_cpy_84.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_src_wchar_t_cpy_84
{
CWE122_Heap_Based_Buffer_Overflow__cpp_src_wchar_t_cpy_84_goodG2B::CWE122_Heap_Based_Buffer_Overflow__cpp_src_wchar_t_cpy_84_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Initialize data as a small buffer that as small or smaller than the small buffer used in the sink */
    wmemset(data, L'A', 50-1); /* fill with L'A's */
    data[50-1] = L'\0'; /* null terminate */
}

CWE122_Heap_Based_Buffer_Overflow__cpp_src_wchar_t_cpy_84_goodG2B::~CWE122_Heap_Based_Buffer_Overflow__cpp_src_wchar_t_cpy_84_goodG2B()
{
    {
        wchar_t dest[50] = L"";
        /* POTENTIAL FLAW: Possible buffer overflow if data is larger than dest */
        wcscpy(dest, data);
        printWLine(data);
        delete [] data;
    }
}
}
#endif /* OMITGOOD */
