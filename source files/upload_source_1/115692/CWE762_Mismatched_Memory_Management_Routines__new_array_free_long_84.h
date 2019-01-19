/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84.h
Label Definition File: CWE762_Mismatched_Memory_Management_Routines__new_array_free.label.xml
Template File: sources-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 762 Mismatched Memory Management Routines
 * BadSource:  Allocate data using new []
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: Deallocate data using delete []
 *    BadSink : Deallocate data using free()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

namespace CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84
{

#ifndef OMITBAD

class CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_bad
{
public:
    CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_bad(long * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_bad();

private:
    long * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_goodG2B
{
public:
    CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_goodG2B(long * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_goodG2B();

private:
    long * data;
};

class CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_goodB2G
{
public:
    CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_goodB2G(long * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__new_array_free_long_84_goodB2G();

private:
    long * data;
};

#endif /* OMITGOOD */

}
