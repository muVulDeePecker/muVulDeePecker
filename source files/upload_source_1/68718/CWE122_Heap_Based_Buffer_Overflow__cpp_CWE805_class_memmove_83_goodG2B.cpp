/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_class_memmove_83_goodG2B.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805.label.xml
Template File: sources-sink-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using new[] and set data pointer to a small buffer
 * GoodSource: Allocate using new[] and set data pointer to a large buffer
 * Sinks: memmove
 *    BadSink : Copy TwoIntsClass array to data using memmove
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_class_memmove_83.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_class_memmove_83
{
CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_class_memmove_83_goodG2B::CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_class_memmove_83_goodG2B(TwoIntsClass * dataCopy)
{
    data = dataCopy;
    /* FIX: Allocate using new[] and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = new TwoIntsClass[100];
}

CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_class_memmove_83_goodG2B::~CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_class_memmove_83_goodG2B()
{
    {
        TwoIntsClass source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memmove(data, source, 100*sizeof(TwoIntsClass));
        printIntLine(data[0].intOne);
        delete [] data;
    }
}
}
#endif /* OMITGOOD */
