/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__int_pointer_64b.c
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c.label.xml
Template File: sources-sinks-64b.tmpl.c
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: no_init Don't initialize data
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 64 Data flow: void pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE457_Use_of_Uninitialized_Variable__int_pointer_64b_badSink(void * dataVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    int * * dataPtr = (int * *)dataVoidPtr;
    /* dereference dataPtr into data */
    int * data = (*dataPtr);
    /* POTENTIAL FLAW: Use data without initializing it */
    printIntLine(*data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE457_Use_of_Uninitialized_Variable__int_pointer_64b_goodG2BSink(void * dataVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    int * * dataPtr = (int * *)dataVoidPtr;
    /* dereference dataPtr into data */
    int * data = (*dataPtr);
    /* POTENTIAL FLAW: Use data without initializing it */
    printIntLine(*data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE457_Use_of_Uninitialized_Variable__int_pointer_64b_goodB2GSink(void * dataVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    int * * dataPtr = (int * *)dataVoidPtr;
    /* dereference dataPtr into data */
    int * data = (*dataPtr);
    /* FIX: Ensure data is initialized before use */
    /* initialize both the pointer and the data pointed to */
    data = (int *)malloc(sizeof(int));
    *data = 5;
    printIntLine(*data);
}

#endif /* OMITGOOD */
