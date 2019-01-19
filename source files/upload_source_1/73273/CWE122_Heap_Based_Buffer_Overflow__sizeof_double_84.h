/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__sizeof.label.xml
Template File: sources-sink-84.tmpl.h
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

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84
{

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84_bad
{
public:
    CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84_bad(double * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84_bad();

private:
    double * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84_goodG2B
{
public:
    CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84_goodG2B(double * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__sizeof_double_84_goodG2B();

private:
    double * data;
};

#endif /* OMITGOOD */

}
