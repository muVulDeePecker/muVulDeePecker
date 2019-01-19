/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE476_NULL_Pointer_Dereference__null_check_after_deref_09.c
Label Definition File: CWE476_NULL_Pointer_Dereference.pointflaw.label.xml
Template File: point-flaw-09.tmpl.c
*/
/*
 * @description
 * CWE: 476 NULL Pointer Dereference
 * Sinks: null_check_after_deref
 *    GoodSink: Do not check for NULL after the pointer has been dereferenced
 *    BadSink : Check for NULL after a pointer has already been dereferenced
 * Flow Variant: 09 Control flow: if(GLOBAL_CONST_TRUE) and if(GLOBAL_CONST_FALSE)
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE476_NULL_Pointer_Dereference__null_check_after_deref_09_bad()
{
    if(GLOBAL_CONST_TRUE)
    {
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
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses if(GLOBAL_CONST_FALSE) instead of if(GLOBAL_CONST_TRUE) */
static void good1()
{
    if(GLOBAL_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            int *intPointer = NULL;
            intPointer = (int *)malloc(sizeof(int));
            *intPointer = 5;
            printIntLine(*intPointer);
            /* FIX: Don't check for NULL since we wouldn't reach this line if the pointer was NULL */
            *intPointer = 10;
            printIntLine(*intPointer);
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(GLOBAL_CONST_TRUE)
    {
        {
            int *intPointer = NULL;
            intPointer = (int *)malloc(sizeof(int));
            *intPointer = 5;
            printIntLine(*intPointer);
            /* FIX: Don't check for NULL since we wouldn't reach this line if the pointer was NULL */
            *intPointer = 10;
            printIntLine(*intPointer);
        }
    }
}

void CWE476_NULL_Pointer_Dereference__null_check_after_deref_09_good()
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
    CWE476_NULL_Pointer_Dereference__null_check_after_deref_09_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE476_NULL_Pointer_Dereference__null_check_after_deref_09_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
