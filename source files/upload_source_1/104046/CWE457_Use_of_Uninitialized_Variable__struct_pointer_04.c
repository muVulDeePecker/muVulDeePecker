/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__struct_pointer_04.c
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c.label.xml
Template File: sources-sinks-04.tmpl.c
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: no_init Don't initialize data
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 04 Control flow: if(STATIC_CONST_TRUE) and if(STATIC_CONST_FALSE)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* The two variables below are declared "const", so a tool should
   be able to identify that reads of these will always return their
   initialized values. */
static const int STATIC_CONST_TRUE = 1; /* true */
static const int STATIC_CONST_FALSE = 0; /* false */

#ifndef OMITBAD

void CWE457_Use_of_Uninitialized_Variable__struct_pointer_04_bad()
{
    twoIntsStruct * data;
    if(STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Don't initialize data */
        ; /* empty statement needed for some flow variants */
    }
    if(STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Use data without initializing it */
        printIntLine(data->intOne);
        printIntLine(data->intTwo);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second STATIC_CONST_TRUE to STATIC_CONST_FALSE */
static void goodB2G1()
{
    twoIntsStruct * data;
    if(STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Don't initialize data */
        ; /* empty statement needed for some flow variants */
    }
    if(STATIC_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Ensure data is initialized before use */
        /* initialize both the pointer and the data pointed to */
        data = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
        data->intOne = 5;
        data->intTwo = 6;
        printIntLine(data->intOne);
        printIntLine(data->intTwo);
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    twoIntsStruct * data;
    if(STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Don't initialize data */
        ; /* empty statement needed for some flow variants */
    }
    if(STATIC_CONST_TRUE)
    {
        /* FIX: Ensure data is initialized before use */
        /* initialize both the pointer and the data pointed to */
        data = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
        data->intOne = 5;
        data->intTwo = 6;
        printIntLine(data->intOne);
        printIntLine(data->intTwo);
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first STATIC_CONST_TRUE to STATIC_CONST_FALSE */
static void goodG2B1()
{
    twoIntsStruct * data;
    if(STATIC_CONST_FALSE)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Initialize data */
        /* initialize both the pointer and the data pointed to */
        data = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
        data->intOne = 5;
        data->intTwo = 6;
    }
    if(STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Use data without initializing it */
        printIntLine(data->intOne);
        printIntLine(data->intTwo);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    twoIntsStruct * data;
    if(STATIC_CONST_TRUE)
    {
        /* FIX: Initialize data */
        /* initialize both the pointer and the data pointed to */
        data = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
        data->intOne = 5;
        data->intTwo = 6;
    }
    if(STATIC_CONST_TRUE)
    {
        /* POTENTIAL FLAW: Use data without initializing it */
        printIntLine(data->intOne);
        printIntLine(data->intTwo);
    }
}

void CWE457_Use_of_Uninitialized_Variable__struct_pointer_04_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B1();
    goodG2B2();
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
    CWE457_Use_of_Uninitialized_Variable__struct_pointer_04_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE457_Use_of_Uninitialized_Variable__struct_pointer_04_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
