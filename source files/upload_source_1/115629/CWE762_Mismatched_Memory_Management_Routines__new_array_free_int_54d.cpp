/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE762_Mismatched_Memory_Management_Routines__new_array_free_int_54d.cpp
Label Definition File: CWE762_Mismatched_Memory_Management_Routines__new_array_free.label.xml
Template File: sources-sinks-54d.tmpl.cpp
*/
/*
 * @description
 * CWE: 762 Mismatched Memory Management Routines
 * BadSource:  Allocate data using new []
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: Deallocate data using delete []
 *    BadSink : Deallocate data using free()
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

namespace CWE762_Mismatched_Memory_Management_Routines__new_array_free_int_54
{

#ifndef OMITBAD

/* bad function declaration */
void badSink_e(int * data);

void badSink_d(int * data)
{
    badSink_e(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink_e(int * data);

void goodG2BSink_d(int * data)
{
    goodG2BSink_e(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink_e(int * data);

void goodB2GSink_d(int * data)
{
    goodB2GSink_e(data);
}

#endif /* OMITGOOD */

} /* close namespace */
