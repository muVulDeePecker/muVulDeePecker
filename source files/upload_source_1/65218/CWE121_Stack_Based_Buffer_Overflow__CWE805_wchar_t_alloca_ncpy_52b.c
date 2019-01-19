/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_52b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.string.label.xml
Template File: sources-sink-52b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: ncpy
 *    BadSink : Copy string to data using wcsncpy
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_52c_badSink(wchar_t * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_52b_badSink(wchar_t * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_52c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_52c_goodG2BSink(wchar_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_52b_goodG2BSink(wchar_t * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_ncpy_52c_goodG2BSink(data);
}

#endif /* OMITGOOD */
