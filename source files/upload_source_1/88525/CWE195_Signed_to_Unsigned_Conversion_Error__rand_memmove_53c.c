/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE195_Signed_to_Unsigned_Conversion_Error__rand_memmove_53c.c
Label Definition File: CWE195_Signed_to_Unsigned_Conversion_Error.label.xml
Template File: sources-sink-53c.tmpl.c
*/
/*
 * @description
 * CWE: 195 Signed to Unsigned Conversion Error
 * BadSource: rand Set data to result of rand(), which may be zero
 * GoodSource: Positive integer
 * Sink: memmove
 *    BadSink : Copy strings using memmove() with the length of data
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE195_Signed_to_Unsigned_Conversion_Error__rand_memmove_53d_badSink(int data);

void CWE195_Signed_to_Unsigned_Conversion_Error__rand_memmove_53c_badSink(int data)
{
    CWE195_Signed_to_Unsigned_Conversion_Error__rand_memmove_53d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE195_Signed_to_Unsigned_Conversion_Error__rand_memmove_53d_goodG2BSink(int data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE195_Signed_to_Unsigned_Conversion_Error__rand_memmove_53c_goodG2BSink(int data)
{
    CWE195_Signed_to_Unsigned_Conversion_Error__rand_memmove_53d_goodG2BSink(data);
}

#endif /* OMITGOOD */
