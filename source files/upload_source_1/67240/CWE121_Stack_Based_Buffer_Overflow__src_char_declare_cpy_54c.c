/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_54c.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__src.label.xml
Template File: sources-sink-54c.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Initialize data as a large string
 * GoodSource: Initialize data as a small string
 * Sink: cpy
 *    BadSink : Copy data to string using strcpy
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_54d_badSink(char * data);

void CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_54c_badSink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_54d_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_54c_goodG2BSink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_54d_goodG2BSink(data);
}

#endif /* OMITGOOD */
