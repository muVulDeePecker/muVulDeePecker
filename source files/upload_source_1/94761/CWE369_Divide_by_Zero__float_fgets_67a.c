/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__float_fgets_67a.c
Label Definition File: CWE369_Divide_by_Zero__float.label.xml
Template File: sources-sinks-67a.tmpl.c
*/
/*
 * @description
 * CWE: 369 Divide by Zero
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: A hardcoded non-zero number (two)
 * Sinks:
 *    GoodSink: Check value of or near zero before dividing
 *    BadSink : Divide a constant by data
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <math.h>

#define CHAR_ARRAY_SIZE 20

typedef struct _CWE369_Divide_by_Zero__float_fgets_67_structType
{
    float structFirst;
} CWE369_Divide_by_Zero__float_fgets_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE369_Divide_by_Zero__float_fgets_67b_badSink(CWE369_Divide_by_Zero__float_fgets_67_structType myStruct);

void CWE369_Divide_by_Zero__float_fgets_67_bad()
{
    float data;
    CWE369_Divide_by_Zero__float_fgets_67_structType myStruct;
    /* Initialize data */
    data = 0.0F;
    {
        char inputBuffer[CHAR_ARRAY_SIZE];
        /* POTENTIAL FLAW: Use a value input from the console using fgets() */
        if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
        {
            /* Convert to float */
            data = (float)atof(inputBuffer);
        }
        else
        {
            printLine("fgets() failed.");
        }
    }
    myStruct.structFirst = data;
    CWE369_Divide_by_Zero__float_fgets_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE369_Divide_by_Zero__float_fgets_67b_goodG2BSink(CWE369_Divide_by_Zero__float_fgets_67_structType myStruct);

static void goodG2B()
{
    float data;
    CWE369_Divide_by_Zero__float_fgets_67_structType myStruct;
    /* Initialize data */
    data = 0.0F;
    /* FIX: Use a hardcoded number that won't a divide by zero */
    data = 2.0F;
    myStruct.structFirst = data;
    CWE369_Divide_by_Zero__float_fgets_67b_goodG2BSink(myStruct);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE369_Divide_by_Zero__float_fgets_67b_goodB2GSink(CWE369_Divide_by_Zero__float_fgets_67_structType myStruct);

static void goodB2G()
{
    float data;
    CWE369_Divide_by_Zero__float_fgets_67_structType myStruct;
    /* Initialize data */
    data = 0.0F;
    {
        char inputBuffer[CHAR_ARRAY_SIZE];
        /* POTENTIAL FLAW: Use a value input from the console using fgets() */
        if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
        {
            /* Convert to float */
            data = (float)atof(inputBuffer);
        }
        else
        {
            printLine("fgets() failed.");
        }
    }
    myStruct.structFirst = data;
    CWE369_Divide_by_Zero__float_fgets_67b_goodB2GSink(myStruct);
}

void CWE369_Divide_by_Zero__float_fgets_67_good()
{
    goodG2B();
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE369_Divide_by_Zero__float_fgets_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE369_Divide_by_Zero__float_fgets_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
