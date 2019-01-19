/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_loop_82_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805.string.label.xml
Template File: sources-sink-82_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using new[] and set data pointer to a small buffer
 * GoodSource: Allocate using new[] and set data pointer to a large buffer
 * Sinks: loop
 *    BadSink : Copy string to data using a loop
 * Flow Variant: 82 Data flow: data passed in a parameter to a virtual method called via a pointer
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_loop_82.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_loop_82
{

void CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_loop_82_bad::action(char * data)
{
    {
        size_t i;
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than data */
        for (i = 0; i < 100; i++)
        {
            data[i] = source[i];
        }
        data[100-1] = '\0'; /* Ensure the destination buffer is null terminated */
        printLine(data);
        delete [] data;
    }
}

}
#endif /* OMITBAD */
