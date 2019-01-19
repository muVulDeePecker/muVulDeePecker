/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__char_alloca_memmove_81_goodG2B.cpp
Label Definition File: CWE124_Buffer_Underwrite.stack.label.xml
Template File: sources-sink-81_goodG2B.tmpl.cpp
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
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE124_Buffer_Underwrite__char_alloca_memmove_81.h"

namespace CWE124_Buffer_Underwrite__char_alloca_memmove_81
{

void CWE124_Buffer_Underwrite__char_alloca_memmove_81_goodG2B::action(char * data) const
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
    }
}

}
#endif /* OMITGOOD */
