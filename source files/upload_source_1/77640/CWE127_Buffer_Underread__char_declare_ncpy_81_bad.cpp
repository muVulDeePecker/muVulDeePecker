/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__char_declare_ncpy_81_bad.cpp
Label Definition File: CWE127_Buffer_Underread.stack.label.xml
Template File: sources-sink-81_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sinks: ncpy
 *    BadSink : Copy data to string using strncpy
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE127_Buffer_Underread__char_declare_ncpy_81.h"

namespace CWE127_Buffer_Underread__char_declare_ncpy_81
{

void CWE127_Buffer_Underread__char_declare_ncpy_81_bad::action(char * data) const
{
    {
        char dest[100];
        memset(dest, 'C', 100-1); /* fill with 'C's */
        dest[100-1] = '\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copy from a memory location located before the source buffer */
        strncpy(dest, data, strlen(dest));
        /* Ensure null termination */
        dest[100-1] = '\0';
        printLine(dest);
    }
}

}
#endif /* OMITBAD */
