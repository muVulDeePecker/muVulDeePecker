/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__malloc_wchar_t_loop_53c.c
Label Definition File: CWE124_Buffer_Underwrite__malloc.label.xml
Template File: sources-sink-53c.tmpl.c
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sink: loop
 *    BadSink : Copy string to data using a loop
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE124_Buffer_Underwrite__malloc_wchar_t_loop_53d_badSink(wchar_t * data);

void CWE124_Buffer_Underwrite__malloc_wchar_t_loop_53c_badSink(wchar_t * data)
{
    CWE124_Buffer_Underwrite__malloc_wchar_t_loop_53d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE124_Buffer_Underwrite__malloc_wchar_t_loop_53d_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE124_Buffer_Underwrite__malloc_wchar_t_loop_53c_goodG2BSink(wchar_t * data)
{
    CWE124_Buffer_Underwrite__malloc_wchar_t_loop_53d_goodG2BSink(data);
}

#endif /* OMITGOOD */
