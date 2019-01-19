/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__new_char_cpy_82_goodG2B.cpp
Label Definition File: CWE127_Buffer_Underread__new.label.xml
Template File: sources-sink-82_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sinks: cpy
 *    BadSink : Copy data to string using strcpy
 * Flow Variant: 82 Data flow: data passed in a parameter to a virtual method called via a pointer
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE127_Buffer_Underread__new_char_cpy_82.h"

namespace CWE127_Buffer_Underread__new_char_cpy_82
{

void CWE127_Buffer_Underread__new_char_cpy_82_goodG2B::action(char * data)
{
    {
        char dest[100*2];
        memset(dest, 'C', 100*2-1); /* fill with 'C's */
        dest[100*2-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copy from a memory location located before the source buffer */
        strcpy(dest, data);
        printLine(dest);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by new [] so can't safely call delete [] on it */
    }
}

}
#endif /* OMITGOOD */
