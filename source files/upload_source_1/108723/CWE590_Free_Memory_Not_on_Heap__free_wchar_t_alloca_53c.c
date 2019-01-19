/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE590_Free_Memory_Not_on_Heap__free_wchar_t_alloca_53c.c
Label Definition File: CWE590_Free_Memory_Not_on_Heap__free.label.xml
Template File: sources-sink-53c.tmpl.c
*/
/*
 * @description
 * CWE: 590 Free Memory Not on Heap
 * BadSource: alloca Data buffer is allocated on the stack with alloca()
 * GoodSource: Allocate memory on the heap
 * Sink:
 *    BadSink : Print then free data
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE590_Free_Memory_Not_on_Heap__free_wchar_t_alloca_53d_badSink(wchar_t * data);

void CWE590_Free_Memory_Not_on_Heap__free_wchar_t_alloca_53c_badSink(wchar_t * data)
{
    CWE590_Free_Memory_Not_on_Heap__free_wchar_t_alloca_53d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE590_Free_Memory_Not_on_Heap__free_wchar_t_alloca_53d_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE590_Free_Memory_Not_on_Heap__free_wchar_t_alloca_53c_goodG2BSink(wchar_t * data)
{
    CWE590_Free_Memory_Not_on_Heap__free_wchar_t_alloca_53d_goodG2BSink(data);
}

#endif /* OMITGOOD */
