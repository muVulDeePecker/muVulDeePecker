/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__struct_pointer_18.c
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c.label.xml
Template File: sources-sinks-18.tmpl.c
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: no_init Don't initialize data
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 18 Control flow: goto statements
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE457_Use_of_Uninitialized_Variable__struct_pointer_18_bad()
{
    twoIntsStruct * data;
    goto source;
source:
    /* POTENTIAL FLAW: Don't initialize data */
    ; /* empty statement needed for some flow variants */
    goto sink;
sink:
    /* POTENTIAL FLAW: Use data without initializing it */
    printIntLine(data->intOne);
    printIntLine(data->intTwo);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() - use badsource and goodsink by reversing the blocks on the second goto statement */
static void goodB2G()
{
    twoIntsStruct * data;
    goto source;
source:
    /* POTENTIAL FLAW: Don't initialize data */
    ; /* empty statement needed for some flow variants */
    goto sink;
sink:
    /* FIX: Ensure data is initialized before use */
    /* initialize both the pointer and the data pointed to */
    data = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
    data->intOne = 5;
    data->intTwo = 6;
    printIntLine(data->intOne);
    printIntLine(data->intTwo);
}

/* goodG2B() - use goodsource and badsink by reversing the blocks on the first goto statement */
static void goodG2B()
{
    twoIntsStruct * data;
    goto source;
source:
    /* FIX: Initialize data */
    /* initialize both the pointer and the data pointed to */
    data = (twoIntsStruct *)malloc(sizeof(twoIntsStruct));
    data->intOne = 5;
    data->intTwo = 6;
    goto sink;
sink:
    /* POTENTIAL FLAW: Use data without initializing it */
    printIntLine(data->intOne);
    printIntLine(data->intTwo);
}

void CWE457_Use_of_Uninitialized_Variable__struct_pointer_18_good()
{
    goodB2G();
    goodG2B();
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
    CWE457_Use_of_Uninitialized_Variable__struct_pointer_18_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE457_Use_of_Uninitialized_Variable__struct_pointer_18_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
