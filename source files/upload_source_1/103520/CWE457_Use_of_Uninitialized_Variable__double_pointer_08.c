/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__double_pointer_08.c
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c.label.xml
Template File: sources-sinks-08.tmpl.c
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: no_init Don't initialize data
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 08 Control flow: if(staticReturnsTrue()) and if(staticReturnsFalse())
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

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

void CWE457_Use_of_Uninitialized_Variable__double_pointer_08_bad()
{
    double * data;
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Don't initialize data */
        ; /* empty statement needed for some flow variants */
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Use data without initializing it */
        printDoubleLine(*data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second staticReturnsTrue() to staticReturnsFalse() */
static void goodB2G1()
{
    double * data;
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Don't initialize data */
        ; /* empty statement needed for some flow variants */
    }
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Ensure data is initialized before use */
        /* initialize both the pointer and the data pointed to */
        data = (double *)malloc(sizeof(double));
        *data = 5.0;
        printDoubleLine(*data);
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    double * data;
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Don't initialize data */
        ; /* empty statement needed for some flow variants */
    }
    if(staticReturnsTrue())
    {
        /* FIX: Ensure data is initialized before use */
        /* initialize both the pointer and the data pointed to */
        data = (double *)malloc(sizeof(double));
        *data = 5.0;
        printDoubleLine(*data);
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first staticReturnsTrue() to staticReturnsFalse() */
static void goodG2B1()
{
    double * data;
    if(staticReturnsFalse())
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Initialize data */
        /* initialize both the pointer and the data pointed to */
        data = (double *)malloc(sizeof(double));
        *data = 5.0;
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Use data without initializing it */
        printDoubleLine(*data);
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    double * data;
    if(staticReturnsTrue())
    {
        /* FIX: Initialize data */
        /* initialize both the pointer and the data pointed to */
        data = (double *)malloc(sizeof(double));
        *data = 5.0;
    }
    if(staticReturnsTrue())
    {
        /* POTENTIAL FLAW: Use data without initializing it */
        printDoubleLine(*data);
    }
}

void CWE457_Use_of_Uninitialized_Variable__double_pointer_08_good()
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
    CWE457_Use_of_Uninitialized_Variable__double_pointer_08_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE457_Use_of_Uninitialized_Variable__double_pointer_08_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
