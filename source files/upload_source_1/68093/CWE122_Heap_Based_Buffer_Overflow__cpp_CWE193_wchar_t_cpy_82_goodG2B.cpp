/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_cpy_82_goodG2B.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193.label.xml
Template File: sources-sink-82_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sinks: cpy
 *    BadSink : Copy string to data using wcscpy()
 * Flow Variant: 82 Data flow: data passed in a parameter to a virtual method called via a pointer
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_cpy_82.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_cpy_82
{

void CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_wchar_t_cpy_82_goodG2B::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        wcscpy(data, source);
        printWLine(data);
        delete [] data;
    }
}

}
#endif /* OMITGOOD */
