/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__float_fgets_32.c
Label Definition File: CWE369_Divide_by_Zero__float.label.xml
Template File: sources-sinks-32.tmpl.c
*/
/*
 * @description
 * CWE: 369 Divide by Zero
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: A hardcoded non-zero number (two)
 * Sinks:
 *    GoodSink: Check value of or near zero before dividing
 *    BadSink : Divide a constant by data
 * Flow Variant: 32 Data flow using two pointers to the same value within the same function
 *
 * */

#include "std_testcase.h"

#include <math.h>

#define CHAR_ARRAY_SIZE 20

#ifndef OMITBAD

void CWE369_Divide_by_Zero__float_fgets_32_bad()
{
    float data;
    float *dataPtr1 = &data;
    float *dataPtr2 = &data;
    /* Initialize data */
    data = 0.0F;
    {
        float data = *dataPtr1;
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
        *dataPtr1 = data;
    }
    {
        float data = *dataPtr2;
        {
            /* POTENTIAL FLAW: Possibly divide by zero */
            int result = (int)(100.0 / data);
            printIntLine(result);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2B()
{
    float data;
    float *dataPtr1 = &data;
    float *dataPtr2 = &data;
    /* Initialize data */
    data = 0.0F;
    {
        float data = *dataPtr1;
        /* FIX: Use a hardcoded number that won't a divide by zero */
        data = 2.0F;
        *dataPtr1 = data;
    }
    {
        float data = *dataPtr2;
        {
            /* POTENTIAL FLAW: Possibly divide by zero */
            int result = (int)(100.0 / data);
            printIntLine(result);
        }
    }
}

/* goodB2G() uses the BadSource with the GoodSink */
static void goodB2G()
{
    float data;
    float *dataPtr1 = &data;
    float *dataPtr2 = &data;
    /* Initialize data */
    data = 0.0F;
    {
        float data = *dataPtr1;
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
        *dataPtr1 = data;
    }
    {
        float data = *dataPtr2;
        /* FIX: Check for value of or near zero before dividing */
        if(fabs(data) > 0.000001)
        {
            int result = (int)(100.0 / data);
            printIntLine(result);
        }
        else
        {
            printLine("This would result in a divide by zero");
        }
    }
}

void CWE369_Divide_by_Zero__float_fgets_32_good()
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
    CWE369_Divide_by_Zero__float_fgets_32_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE369_Divide_by_Zero__float_fgets_32_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
