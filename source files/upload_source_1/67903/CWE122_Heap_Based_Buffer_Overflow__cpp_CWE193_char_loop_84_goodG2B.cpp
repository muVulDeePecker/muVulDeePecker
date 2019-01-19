/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_loop_84_goodG2B.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate memory for a string, but do not allocate space for NULL terminator
 * GoodSource: Allocate enough memory for a string and the NULL terminator
 * Sinks: loop
 *    BadSink : Copy array to data using a loop
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_loop_84.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_loop_84
{
CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_loop_84_goodG2B::CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_loop_84_goodG2B(char * dataCopy)
{
    data = dataCopy;
    /* FIX: Allocate space for a null terminator */
    data = new char[10+1];
}

CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_loop_84_goodG2B::~CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_loop_84_goodG2B()
{
    {
        char source[10+1] = SRC_STRING;
        size_t i, sourceLen;
        sourceLen = strlen(source);
        /* Copy length + 1 to include NUL terminator from source */
        /* POTENTIAL FLAW: data may not have enough space to hold source */
        for (i = 0; i < sourceLen + 1; i++)
        {
            data[i] = source[i];
        }
        printLine(data);
        delete [] data;
    }
}
}
#endif /* OMITGOOD */
