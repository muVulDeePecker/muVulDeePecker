/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84.h
Label Definition File: CWE762_Mismatched_Memory_Management_Routines__delete.label.xml
Template File: sources-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 762 Mismatched Memory Management Routines
 * BadSource: realloc Allocate data using realloc()
 * GoodSource: Allocate data using new
 * Sinks:
 *    GoodSink: Deallocate data using free()
 *    BadSink : Deallocate data using delete
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

namespace CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84
{

#ifndef OMITBAD

class CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_bad
{
public:
    CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_bad(wchar_t * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_bad();

private:
    wchar_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_goodG2B
{
public:
    CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_goodG2B(wchar_t * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_goodG2B();

private:
    wchar_t * data;
};

class CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_goodB2G
{
public:
    CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_goodB2G(wchar_t * dataCopy);
    ~CWE762_Mismatched_Memory_Management_Routines__delete_wchar_t_realloc_84_goodB2G();

private:
    wchar_t * data;
};

#endif /* OMITGOOD */

}
