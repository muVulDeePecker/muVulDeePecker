/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__malloc_char_loop_84_goodG2B.cpp
Label Definition File: CWE126_Buffer_Overread__malloc.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 126 Buffer Over-read
 * BadSource:  Use a small buffer
 * GoodSource: Use a large buffer
 * Sinks: loop
 *    BadSink : Copy data to string using a loop
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE126_Buffer_Overread__malloc_char_loop_84.h"

namespace CWE126_Buffer_Overread__malloc_char_loop_84
{
CWE126_Buffer_Overread__malloc_char_loop_84_goodG2B::CWE126_Buffer_Overread__malloc_char_loop_84_goodG2B(char * dataCopy)
{
    data = dataCopy;
    /* FIX: Use a large buffer */
    data = (char *)malloc(100*sizeof(char));
    memset(data, 'A', 100-1); /* fill with 'A's */
    data[100-1] = '\0'; /* null terminate */
}

CWE126_Buffer_Overread__malloc_char_loop_84_goodG2B::~CWE126_Buffer_Overread__malloc_char_loop_84_goodG2B()
{
    {
        size_t i, destLen;
        char dest[100];
        memset(dest, 'C', 100-1);
        dest[100-1] = '\0'; /* null terminate */
        destLen = strlen(dest);
        /* POTENTIAL FLAW: using length of the dest where data
         * could be smaller than dest causing buffer overread */
        for (i = 0; i < destLen; i++)
        {
            dest[i] = data[i];
        }
        dest[100-1] = '\0';
        printLine(dest);
        free(data);
    }
}
}
#endif /* OMITGOOD */
