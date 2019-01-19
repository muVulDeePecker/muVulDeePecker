/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__malloc_char_loop_84_goodG2B.cpp
Label Definition File: CWE127_Buffer_Underread__malloc.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sinks: loop
 *    BadSink : Copy data to string using a loop
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE127_Buffer_Underread__malloc_char_loop_84.h"

namespace CWE127_Buffer_Underread__malloc_char_loop_84
{
CWE127_Buffer_Underread__malloc_char_loop_84_goodG2B::CWE127_Buffer_Underread__malloc_char_loop_84_goodG2B(char * dataCopy)
{
    data = dataCopy;
    {
        char * dataBuffer = (char *)malloc(100*sizeof(char));
        memset(dataBuffer, 'A', 100-1);
        dataBuffer[100-1] = '\0';
        /* FIX: Set data pointer to the allocated memory buffer */
        data = dataBuffer;
    }
}

CWE127_Buffer_Underread__malloc_char_loop_84_goodG2B::~CWE127_Buffer_Underread__malloc_char_loop_84_goodG2B()
{
    {
        size_t i;
        char dest[100];
        memset(dest, 'C', 100-1); /* fill with 'C's */
        dest[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copy from a memory location located before the source buffer */
        for (i = 0; i < 100; i++)
        {
            dest[i] = data[i];
        }
        /* Ensure null termination */
        dest[100-1] = '\0';
        printLine(dest);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by malloc() so can't safely call free() on it */
    }
}
}
#endif /* OMITGOOD */
