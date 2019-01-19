/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE762_Mismatched_Memory_Management_Routines__delete_struct_calloc_54c.cpp
Label Definition File: CWE762_Mismatched_Memory_Management_Routines__delete.label.xml
Template File: sources-sinks-54c.tmpl.cpp
*/
/*
 * @description
 * CWE: 762 Mismatched Memory Management Routines
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data using new
 * Sinks:
 *    GoodSink: Deallocate data using free()
 *    BadSink : Deallocate data using delete
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

namespace CWE762_Mismatched_Memory_Management_Routines__delete_struct_calloc_54
{

#ifndef OMITBAD

/* bad function declaration */
void badSink_d(twoIntsStruct * data);

void badSink_c(twoIntsStruct * data)
{
    badSink_d(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink_d(twoIntsStruct * data);

void goodG2BSink_c(twoIntsStruct * data)
{
    goodG2BSink_d(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink_d(twoIntsStruct * data);

void goodB2GSink_c(twoIntsStruct * data)
{
    goodB2GSink_d(data);
}

#endif /* OMITGOOD */

} /* close namespace */
