/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE758_Undefined_Behavior__char_pointer_malloc_use_05.c
Label Definition File: CWE758_Undefined_Behavior.alloc.label.xml
Template File: point-flaw-05.tmpl.c
*/
/*
 * @description
 * CWE: 758 Undefined Behavior
 * Sinks: malloc_use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data from malloc without initialization
 * Flow Variant: 05 Control flow: if(staticTrue) and if(staticFalse)
 *
 * */

#include "std_testcase.h"

/* The two variables below are not defined as "const", but are never
   assigned any other value, so a tool should be able to identify that
   reads of these will always return their initialized values. */
static int staticTrue = 1; /* true */
static int staticFalse = 0; /* false */

#ifndef OMITBAD

void CWE758_Undefined_Behavior__char_pointer_malloc_use_05_bad()
{
    if(staticTrue)
    {
        {
            char * * pointer = (char * *)malloc(sizeof(char *));
            char * data = *pointer; /* FLAW: the value pointed to by pointer is undefined */
            free(pointer);
            printLine(data);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good1() uses if(staticFalse) instead of if(staticTrue) */
static void good1()
{
    if(staticFalse)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        {
            char * data;
            char * * pointer = (char * *)malloc(sizeof(char *));
            data = "string";
            *pointer = data; /* FIX: Assign a value to the thing pointed to by pointer */
            {
                char * data = *pointer;
                printLine(data);
            }
            free(pointer);
        }
    }
}

/* good2() reverses the bodies in the if statement */
static void good2()
{
    if(staticTrue)
    {
        {
            char * data;
            char * * pointer = (char * *)malloc(sizeof(char *));
            data = "string";
            *pointer = data; /* FIX: Assign a value to the thing pointed to by pointer */
            {
                char * data = *pointer;
                printLine(data);
            }
            free(pointer);
        }
    }
}

void CWE758_Undefined_Behavior__char_pointer_malloc_use_05_good()
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
    CWE758_Undefined_Behavior__char_pointer_malloc_use_05_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE758_Undefined_Behavior__char_pointer_malloc_use_05_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
