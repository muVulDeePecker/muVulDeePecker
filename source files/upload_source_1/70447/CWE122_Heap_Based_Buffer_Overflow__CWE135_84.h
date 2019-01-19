/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__CWE135_84.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Void pointer to a wchar_t array
 * GoodSource: Void pointer to a char array
 * Sinks:
 *    GoodSink: Allocate memory using wcslen() and copy data
 *    BadSink : Allocate memory using strlen() and copy data
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE122_Heap_Based_Buffer_Overflow__CWE135_84
{

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__CWE135_84_bad
{
public:
    CWE122_Heap_Based_Buffer_Overflow__CWE135_84_bad(void * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__CWE135_84_bad();

private:
    void * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__CWE135_84_goodG2B
{
public:
    CWE122_Heap_Based_Buffer_Overflow__CWE135_84_goodG2B(void * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__CWE135_84_goodG2B();

private:
    void * data;
};

class CWE122_Heap_Based_Buffer_Overflow__CWE135_84_goodB2G
{
public:
    CWE122_Heap_Based_Buffer_Overflow__CWE135_84_goodB2G(void * dataCopy);
    ~CWE122_Heap_Based_Buffer_Overflow__CWE135_84_goodB2G();

private:
    void * data;
};

#endif /* OMITGOOD */

}
