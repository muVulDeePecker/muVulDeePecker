/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__short_fgets_67a.c
Label Definition File: CWE197_Numeric_Truncation_Error__short.label.xml
Template File: sources-sink-67a.tmpl.c
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

/* bad function declaration */
void CWE197_Numeric_Truncation_Error__short_fgets_67b_badSink(CWE197_Numeric_Truncation_Error__short_fgets_67_structType myStruct);

void CWE197_Numeric_Truncation_Error__short_fgets_67_bad()
{
    short data;
    CWE197_Numeric_Truncation_Error__short_fgets_67_structType myStruct;
    /* Initialize data */
    data = -1;
    {
        char inputBuffer[CHAR_ARRAY_SIZE] = "";
        /* FLAW: Use a number input from the console using fgets() */
        if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
        {
            /* Convert to short */
            data = (short)atoi(inputBuffer);
        }
        else
        {
            printLine("fgets() failed.");
        }
    }
    myStruct.structFirst = data;
    CWE197_Numeric_Truncation_Error__short_fgets_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE197_Numeric_Truncation_Error__short_fgets_67b_goodG2BSink(CWE197_Numeric_Truncation_Error__short_fgets_67_structType myStruct);

static void goodG2B()
{
    short data;
    CWE197_Numeric_Truncation_Error__short_fgets_67_structType myStruct;
    /* Initialize data */
    data = -1;
    /* FIX: Use a positive integer less than CHAR_MAX*/
    data = CHAR_MAX-5;
    myStruct.structFirst = data;
    CWE197_Numeric_Truncation_Error__short_fgets_67b_goodG2BSink(myStruct);
}

void CWE197_Numeric_Truncation_Error__short_fgets_67_good()
{
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE197_Numeric_Truncation_Error__short_fgets_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE197_Numeric_Truncation_Error__short_fgets_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
