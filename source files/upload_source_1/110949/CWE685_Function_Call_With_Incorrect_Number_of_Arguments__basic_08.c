/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic_08.c
Label Definition File: CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic.label.xml
Template File: point-flaw-08.tmpl.c
*/
/*
 * @description
 * CWE: 685 Function Call With Incorrect Number of Arguments
 * Sinks:
 *    GoodSink: Use the correct number of arguments
 *    BadSink : Incorrect number of arguments
 * Flow Variant: 08 Control flow: if(staticReturnsTrue()) and if(staticReturnsFalse())
 *
 * */

#include "std_testcase.h"

#define DEST_SIZE 100 /* maintenance note: ensure this is > 2*SOURCE_STRING to avoid buffer overflow issues */
#define SOURCE_STRING "AAA"

/* The two function below always return the same value, so a tool
   should be able to identify that calls to the functions will always
   return a fixed value. */
static int staticReturnsTrue()
{
    return 1;
}

static int staticReturnsFalse()
{
    return 0;
}

#ifndef OMITBAD

void CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic_08_bad()
{
    if(staticReturnsTrue())
    {
        {
            char dest[DEST_SIZE];
            /* FLAW: Incorrect number of arguments */
            sprintf(dest, "%s %s", SOURCE_STRING);
            printLine(dest);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses if(staticReturnsFalse()) instead of if(staticReturnsTrue()) */
static void good1()
{
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            char dest[DEST_SIZE];
            /* FIX: Use the correct number of arguments */
            sprintf(dest, "%s %s", SOURCE_STRING, SOURCE_STRING);
            printLine(dest);
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(staticReturnsTrue())
    {
        {
            char dest[DEST_SIZE];
            /* FIX: Use the correct number of arguments */
            sprintf(dest, "%s %s", SOURCE_STRING, SOURCE_STRING);
            printLine(dest);
        }
    }
}

void CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic_08_good()
{
    good1();
    good2();
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
    CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic_08_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE685_Function_Call_With_Incorrect_Number_of_Arguments__basic_08_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
