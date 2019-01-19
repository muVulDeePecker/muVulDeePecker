/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sinks: loop
 *    BadSink : Copy data to string using a loop
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84
{

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84_bad
{
public:
    CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84_bad(wchar_t * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84_bad();

private:
    wchar_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84_goodG2B
{
public:
    CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84_goodG2B(wchar_t * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__cpp_CWE806_wchar_t_loop_84_goodG2B();

private:
    wchar_t * data;
};

#endif /* OMITGOOD */

}
