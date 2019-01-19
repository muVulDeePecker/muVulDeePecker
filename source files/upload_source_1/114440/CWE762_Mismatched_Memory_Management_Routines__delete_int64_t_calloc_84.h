/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84.h
Label Definition File: CWE762_Mismatched_Memory_Management_Routines__delete.label.xml
Template File: sources-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 762 Mismatched Memory Management Routines
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data using new
 * Sinks:
 *    GoodSink: Deallocate data using free()
 *    BadSink : Deallocate data using delete
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

namespace CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84
{

#ifndef OMITBAD

class CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_bad
{
public:
    CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_bad(int64_t * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_bad();

private:
    int64_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_goodG2B
{
public:
    CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_goodG2B(int64_t * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_goodG2B();

private:
    int64_t * data;
};

class CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_goodB2G
{
public:
    CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_goodB2G(int64_t * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__delete_int64_t_calloc_84_goodB2G();

private:
    int64_t * data;
};

#endif /* OMITGOOD */

}
