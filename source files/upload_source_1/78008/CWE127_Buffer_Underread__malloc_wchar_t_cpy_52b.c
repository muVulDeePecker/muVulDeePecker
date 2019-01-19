/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__malloc_wchar_t_cpy_52b.c
Label Definition File: CWE127_Buffer_Underread__malloc.label.xml
Template File: sources-sink-52b.tmpl.c
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sink: cpy
 *    BadSink : Copy data to string using wcscpy
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE127_Buffer_Underread__malloc_wchar_t_cpy_52c_badSink(wchar_t * data);

void CWE127_Buffer_Underread__malloc_wchar_t_cpy_52b_badSink(wchar_t * data)
{
    CWE127_Buffer_Underread__malloc_wchar_t_cpy_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE127_Buffer_Underread__malloc_wchar_t_cpy_52c_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE127_Buffer_Underread__malloc_wchar_t_cpy_52b_goodG2BSink(wchar_t * data)
{
    CWE127_Buffer_Underread__malloc_wchar_t_cpy_52c_goodG2BSink(data);
}

#endif /* OMITGOOD */
