/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__new_wchar_t_memcpy_84_bad.cpp
Label Definition File: CWE124_Buffer_Underwrite__new.label.xml
Template File: sources-sink-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sinks: memcpy
 *    BadSink : Copy string to data using memcpy
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE124_Buffer_Underwrite__new_wchar_t_memcpy_84.h"

namespace CWE124_Buffer_Underwrite__new_wchar_t_memcpy_84
{
CWE124_Buffer_Underwrite__new_wchar_t_memcpy_84_bad::CWE124_Buffer_Underwrite__new_wchar_t_memcpy_84_bad(wchar_t * dataCopy)
{
    data = dataCopy;
    {
        wchar_t * dataBuffer = new wchar_t[100];
        wmemset(dataBuffer, L'A', 100-1);
        dataBuffer[100-1] = L'\0';
        /* FLAW: Set data pointer to before the allocated memory buffer */
        data = dataBuffer - 8;
    }
}

CWE124_Buffer_Underwrite__new_wchar_t_memcpy_84_bad::~CWE124_Buffer_Underwrite__new_wchar_t_memcpy_84_bad()
{
    {
        wchar_t source[100];
        wmemset(source, L'C', 100-1); /* fill with 'C's */
        source[100-1] = L'\0'; /* null terminate */
        /* POTENTIAL FLAW: Possibly copying data to memory before the destination buffer */
        memcpy(data, source, 100*sizeof(wchar_t));
        /* Ensure the destination buffer is null terminated */
        data[100-1] = L'\0';
        printWLine(data);
        /* INCIDENTAL CWE-401: Memory Leak - data may not point to location
         * returned by new [] so can't safely call delete [] on it */
    }
}
}
#endif /* OMITBAD */
