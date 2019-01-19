/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__sizeof_struct_84_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__sizeof.label.xml
Template File: sources-sink-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Initialize the source buffer using the size of a pointer
 * GoodSource: Initialize the source buffer using the size of the DataElementType
 * Sinks:
 *    BadSink : Print then free data
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__sizeof_struct_84.h"

namespace CWE122_Heap_Based_Buffer_Overflow__sizeof_struct_84
{
CWE122_Heap_Based_Buffer_Overflow__sizeof_struct_84_bad::CWE122_Heap_Based_Buffer_Overflow__sizeof_struct_84_bad(twoIntsStruct * dataCopy)
{
    data = dataCopy;
    /* INCIDENTAL: CWE-467 (Use of sizeof() on a pointer type) */
    /* FLAW: Using sizeof the pointer and not the data type in malloc() */
    data = (twoIntsStruct *)malloc(sizeof(data));
    data->intOne = 1;
    data->intTwo = 2;
}

CWE122_Heap_Based_Buffer_Overflow__sizeof_struct_84_bad::~CWE122_Heap_Based_Buffer_Overflow__sizeof_struct_84_bad()
{
    /* POTENTIAL FLAW: Attempt to use data, which may not have enough memory allocated */
    printStructLine(data);
    free(data);
}
}
#endif /* OMITBAD */
