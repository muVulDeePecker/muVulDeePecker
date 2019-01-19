/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__short_fgets_53b.c
Label Definition File: CWE197_Numeric_Truncation_Error__short.label.xml
Template File: sources-sink-53b.tmpl.c
*/
/*
 * @description
 * CWE: 197 Numeric Truncation Error
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Less than CHAR_MAX
 * Sink:
 *    BadSink : Convert data to a char
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

/* Must be at least 8 for atoi() to work properly */
#define CHAR_ARRAY_SIZE 8

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE197_Numeric_Truncation_Error__short_fgets_53c_badSink(short data);

void CWE197_Numeric_Truncation_Error__short_fgets_53b_badSink(short data)
{
    CWE197_Numeric_Truncation_Error__short_fgets_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE197_Numeric_Truncation_Error__short_fgets_53c_goodG2BSink(short data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE197_Numeric_Truncation_Error__short_fgets_53b_goodG2BSink(short data)
{
    CWE197_Numeric_Truncation_Error__short_fgets_53c_goodG2BSink(data);
}

#endif /* OMITGOOD */
