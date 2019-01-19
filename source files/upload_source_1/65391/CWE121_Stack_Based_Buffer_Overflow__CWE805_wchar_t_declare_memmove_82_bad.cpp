/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_82_bad.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.string.label.xml
Template File: sources-sink-82_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sinks: memmove
 *    BadSink : Copy string to data using memmove
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_declare_memmove_82_bad::action(wchar_t * data)
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with L'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */
        memmove(data, source, 100*sizeof(wchar_t));
        data[100-1] = L'\0'; /* Ensure the destination buffer is null terminated */
        printWLine(data);
    }
}

}
#endif /* OMITBAD */
