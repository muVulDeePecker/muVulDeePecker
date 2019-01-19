/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE762_Mismatched_Memory_Management_Routines__delete_array_struct_calloc_84_bad.cpp
Label Definition File: CWE762_Mismatched_Memory_Management_Routines__delete_array.label.xml
Template File: sources-sinks-84_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 762 Mismatched Memory Management Routines
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data using new []
 * Sinks:
 *    GoodSink: Deallocate data using free()
 *    BadSink : Deallocate data using delete []
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE762_Mismatched_Memory_Management_Routines__delete_array_struct_calloc_84.h"

namespace CWE762_Mismatched_Memory_Management_Routines__delete_array_struct_calloc_84
{
CWE762_Mismatched_Memory_Management_Routines__delete_array_struct_calloc_84_bad::CWE762_Mismatched_Memory_Management_Routines__delete_array_struct_calloc_84_bad(twoIntsStruct * dataCopy)
{
    data = dataCopy;
    /* POTENTIAL FLAW: Allocate memory with a function that requires free() to free the memory */
    data = (twoIntsStruct *)calloc(100, sizeof(twoIntsStruct));
}

CWE762_Mismatched_Memory_Management_Routines__delete_array_struct_calloc_84_bad::~CWE762_Mismatched_Memory_Management_Routines__delete_array_struct_calloc_84_bad()
{
    /* POTENTIAL FLAW: Deallocate memory using delete [] - the source memory allocation function may
     * require a call to free() to deallocate the memory */
    delete [] data;
}
}
#endif /* OMITBAD */
