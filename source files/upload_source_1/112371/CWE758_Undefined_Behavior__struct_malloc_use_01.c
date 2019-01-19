/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE758_Undefined_Behavior__struct_malloc_use_01.c
Label Definition File: CWE758_Undefined_Behavior.alloc.label.xml
Template File: point-flaw-01.tmpl.c
*/
/*
 * @description
 * CWE: 758 Undefined Behavior
 * Sinks: malloc_use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data from malloc without initialization
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE758_Undefined_Behavior__struct_malloc_use_01_bad()
{
    {
        twoIntsStruct * pointer = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
        twoIntsStruct data = *pointer; /* FLAW: the value pointed to by pointer is undefined */
        free(pointer);
        printIntLine(data.intOne);
        printIntLine(data.intTwo);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

static void good1()
{
    {
        twoIntsStruct data;
        twoIntsStruct * pointer = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
        data.intOne = 1;
        data.intTwo = 2;
        *pointer = data; /* FIX: Assign a value to the thing pointed to by pointer */
        {
            twoIntsStruct data = *pointer;
            printIntLine(data.intOne);
            printIntLine(data.intTwo);
        }
        free(pointer);
    }
}

void CWE758_Undefined_Behavior__struct_malloc_use_01_good()
{
    good1();
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
    CWE758_Undefined_Behavior__struct_malloc_use_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE758_Undefined_Behavior__struct_malloc_use_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
