/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__malloc_wchar_t_memmove_52c.c
Label Definition File: CWE124_Buffer_Underwrite__malloc.label.xml
Template File: sources-sink-52c.tmpl.c
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sink: memmove
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

void CWE124_Buffer_Underwrite__malloc_wchar_t_memmove_52c_badSink(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with 'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copying data to memory before the destination buffer */
        memmove(data, source, 100*sizeof(wchar_t));
        /* Ensure the destination buffer is null terminated */
        data[100-1] = L'\0';
        printWLine(data);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by malloc() so can't safely call free() on it */
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE124_Buffer_Underwrite__malloc_wchar_t_memmove_52c_goodG2BSink(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with 'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copying data to memory before the destination buffer */
        memmove(data, source, 100*sizeof(wchar_t));
        /* Ensure the destination buffer is null terminated */
        data[100-1] = L'\0';
        printWLine(data);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by malloc() so can't safely call free() on it */
    }
}

#endif /* OMITGOOD */
