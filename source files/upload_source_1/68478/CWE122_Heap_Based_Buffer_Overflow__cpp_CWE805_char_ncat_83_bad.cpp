/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_ncat_83_bad.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805.string.label.xml
Template File: sources-sink-83_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using new[] and set data pointer to a small buffer
 * GoodSource: Allocate using new[] and set data pointer to a large buffer
 * Sinks: ncat
 *    BadSink : Copy string to data using strncat
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_ncat_83.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_ncat_83
{
CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_ncat_83_bad::CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_ncat_83_bad(char * dataCopy)
{
    data = dataCopy;
    /* FLAW: Allocate using new[] and point data to a small buffer that is smaller than the large buffer used in the sinks */
    data = new char[50];
    data[0] = '\0'; /* null terminate */
}

CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_ncat_83_bad::~CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_ncat_83_bad()
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if source is larger than sizeof(data)-strlen(data) */
        strncat(data, source, 100);
        printLine(data);
        delete [] data;
    }
}
}
#endif /* OMITBAD */
