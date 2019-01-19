/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_wchar_t_memcpy_82_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805.string.label.xml
Template File: sources-sink-82_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using new[] and set data pointer to a small buffer
 * GoodSource: Allocate using new[] and set data pointer to a large buffer
 * Sinks: memcpy
 *    BadSink : Copy string to data using memcpy
 * Flow Variant: 82 Data flow: data passed in a parameter to a virtual method called via a pointer
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_wchar_t_memcpy_82.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_wchar_t_memcpy_82
{

void CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_wchar_t_memcpy_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        memcpy(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
        delete [] data;
    }
}

}
#endif /* OMITBAD */
