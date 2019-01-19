/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_54d.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.string.label.xml
Template File: sources-sink-54d.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: ncat
 *    BadSink : Copy string to data using strncat
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_54e_badSink(char * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_54d_badSink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_54e_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_54e_goodG2BSink(char * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_54d_goodG2BSink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_54e_goodG2BSink(data);
}

#endif /* OMITGOOD */
