/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE476_NULL_Pointer_Dereference__null_check_after_deref_15.c
Label Definition File: CWE476_NULL_Pointer_Dereference.pointflaw.label.xml
Template File: point-flaw-15.tmpl.c
*/
/*
 * @description
 * CWE: 476 NULL Pointer Dereference
 * Sinks: null_check_after_deref
 *    GoodSink: Do not check for NULL after the pointer has been dereferenced
 *    BadSink : Check for NULL after a pointer has already been dereferenced
 * Flow Variant: 15 Control flow: switch(6)
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE476_NULL_Pointer_Dereference__null_check_after_deref_15_bad()
{
    switch(6)
    {
    case 6:
    {
        int *intPointer = NULL;
        intPointer = (int *)malloc(sizeof(int));
        *intPointer = 5;
        printIntLine(*intPointer);
        /* FLAW: Check for NULL after dereferencing the pointer. This NULL check is unnecessary. */
        if (intPointer != NULL)
        {
            *intPointer = 10;
        }
        printIntLine(*intPointer);
    }
    break;
    default:
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
        break;
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() changes the switch to switch(5) */
static void good1()
{
    switch(5)
    {
    case 6:
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
        break;
    default:
    {
        int *intPointer = NULL;
        intPointer = (int *)malloc(sizeof(int));
        *intPointer = 5;
        printIntLine(*intPointer);
        /* FIX: Don't check for NULL since we wouldn't reach this line if the pointer was NULL */
        *intPointer = 10;
        printIntLine(*intPointer);
    }
    break;
    }
}

/* good2() reverses the blocks in the switch */
static void good2()
{
    switch(6)
    {
    case 6:
    {
        int *intPointer = NULL;
        intPointer = (int *)malloc(sizeof(int));
        *intPointer = 5;
        printIntLine(*intPointer);
        /* FIX: Don't check for NULL since we wouldn't reach this line if the pointer was NULL */
        *intPointer = 10;
        printIntLine(*intPointer);
    }
    break;
    default:
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
        break;
    }
}

void CWE476_NULL_Pointer_Dereference__null_check_after_deref_15_good()
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
    CWE476_NULL_Pointer_Dereference__null_check_after_deref_15_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE476_NULL_Pointer_Dereference__null_check_after_deref_15_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
