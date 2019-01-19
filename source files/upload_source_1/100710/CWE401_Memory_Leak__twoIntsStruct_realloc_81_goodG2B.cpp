/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__twoIntsStruct_realloc_81_goodG2B.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-81_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: realloc Allocate data using realloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE401_Memory_Leak__twoIntsStruct_realloc_81.h"

namespace CWE401_Memory_Leak__twoIntsStruct_realloc_81
{

void CWE401_Memory_Leak__twoIntsStruct_realloc_81_goodG2B::action(twoIntsStruct * data) const
{
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

}
#endif /* OMITGOOD */
