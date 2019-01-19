/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__short_fgets_67b.c
Label Definition File: CWE197_Numeric_Truncation_Error__short.label.xml
Template File: sources-sink-67b.tmpl.c
*/
/*
 * @description
 * CWE: 197 Numeric Truncation Error
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Less than CHAR_MAX
 * Sinks:
 *    BadSink : Convert data to a char
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

/* Must be at least 8 for atoi() to work properly */
#define CHAR_ARRAY_SIZE 8

typedef struct _CWE197_Numeric_Truncation_Error__short_fgets_67_structType
{
    short structFirst;
} CWE197_Numeric_Truncation_Error__short_fgets_67_structType;

#ifndef OMITBAD

void CWE197_Numeric_Truncation_Error__short_fgets_67b_badSink(CWE197_Numeric_Truncation_Error__short_fgets_67_structType myStruct)
{
    short data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error */
        char charData = (char)data;
        printHexCharLine(charData);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE197_Numeric_Truncation_Error__short_fgets_67b_goodG2BSink(CWE197_Numeric_Truncation_Error__short_fgets_67_structType myStruct)
{
    short data = myStruct.structFirst;
    {
        /* POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error */
        char charData = (char)data;
        printHexCharLine(charData);
    }
}

#endif /* OMITGOOD */
