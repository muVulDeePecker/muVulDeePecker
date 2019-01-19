/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_54b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-54b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: memcpy
 *    BadSink : Copy int64_t array to data using memcpy
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_54c_badSink(int64_t * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_54b_badSink(int64_t * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_54c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_54c_goodG2BSink(int64_t * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_54b_goodG2BSink(int64_t * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_54c_goodG2BSink(data);
}

#endif /* OMITGOOD */
