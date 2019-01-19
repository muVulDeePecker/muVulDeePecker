/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE467_Use_of_sizeof_on_Pointer_Type__int_08.c
Label Definition File: CWE467_Use_of_sizeof_on_Pointer_Type.label.xml
Template File: point-flaw-08.tmpl.c
*/
/*
 * @description
 * CWE: 467 Use of sizeof() on a Pointer Type
 * Sinks: int
 *    GoodSink: Use sizeof() the data type
 *    BadSink : Use sizeof() the pointer and not the data type
 * Flow Variant: 08 Control flow: if(staticReturnsTrue()) and if(staticReturnsFalse())
 *
 * */

#include "std_testcase.h"

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

void CWE467_Use_of_sizeof_on_Pointer_Type__int_08_bad()
{
    if(staticReturnsTrue())
    {
        {
            int * badInt = NULL;
            /* FLAW: Using sizeof the pointer and not the data type in malloc() */
            badInt = (int *)malloc(sizeof(badInt));
            *badInt = 5;
            printIntLine(*badInt);
            free(badInt);
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
            int * goodInt = NULL;
            /* FIX: Using sizeof the data type in malloc() */
            goodInt = (int *)malloc(sizeof(*goodInt));
            *goodInt = 6;
            printIntLine(*goodInt);
            free(goodInt);
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(staticReturnsTrue())
    {
        {
            int * goodInt = NULL;
            /* FIX: Using sizeof the data type in malloc() */
            goodInt = (int *)malloc(sizeof(*goodInt));
            *goodInt = 6;
            printIntLine(*goodInt);
            free(goodInt);
        }
    }
}

void CWE467_Use_of_sizeof_on_Pointer_Type__int_08_good()
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
    CWE467_Use_of_sizeof_on_Pointer_Type__int_08_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE467_Use_of_sizeof_on_Pointer_Type__int_08_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
