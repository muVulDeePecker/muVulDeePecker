/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__int_pointer_63a.c
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c.label.xml
Template File: sources-sinks-63a.tmpl.c
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: no_init Don't initialize data
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 63 Data flow: pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE457_Use_of_Uninitialized_Variable__int_pointer_63b_badSink(int * * dataPtr);

void CWE457_Use_of_Uninitialized_Variable__int_pointer_63_bad()
{
    int * data;
    /* POTENTIAL FLAW: Don't initialize data */
    ; /* empty statement needed for some flow variants */
    CWE457_Use_of_Uninitialized_Variable__int_pointer_63b_badSink(&data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE457_Use_of_Uninitialized_Variable__int_pointer_63b_goodG2BSink(int * * data);

static void goodG2B()
{
    int * data;
    /* FIX: Initialize data */
    /* initialize both the pointer and the data pointed to */
    data = (int *)malloc(sizeof(int));
    *data = 5;
    CWE457_Use_of_Uninitialized_Variable__int_pointer_63b_goodG2BSink(&data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE457_Use_of_Uninitialized_Variable__int_pointer_63b_goodB2GSink(int * * data);

static void goodB2G()
{
    int * data;
    /* POTENTIAL FLAW: Don't initialize data */
    ; /* empty statement needed for some flow variants */
    CWE457_Use_of_Uninitialized_Variable__int_pointer_63b_goodB2GSink(&data);
}

void CWE457_Use_of_Uninitialized_Variable__int_pointer_63_good()
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
    CWE457_Use_of_Uninitialized_Variable__int_pointer_63_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE457_Use_of_Uninitialized_Variable__int_pointer_63_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
