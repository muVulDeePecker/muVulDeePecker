/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__malloc_char_memmove_81_bad.cpp
Label Definition File: CWE124_Buffer_Underwrite__malloc.label.xml
Template File: sources-sink-81_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sinks: memmove
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE124_Buffer_Underwrite__malloc_char_memmove_81.h"

namespace CWE124_Buffer_Underwrite__malloc_char_memmove_81
{

void CWE124_Buffer_Underwrite__malloc_char_memmove_81_bad::action(char * data) const
{
    {
        char source[100];
        memset(source, 'C', 100-1); /* fill with 'C's */
        source[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copying data to memory before the destination buffer */
        memmove(data, source, 100*sizeof(char));
        /* Ensure the destination buffer is null terminated */
        data[100-1] = '\0';
        printLine(data);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by malloc() so can't safely call free() on it */
    }
}

}
#endif /* OMITBAD */
