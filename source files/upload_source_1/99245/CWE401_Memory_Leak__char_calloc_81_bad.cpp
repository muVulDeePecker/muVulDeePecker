/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__char_calloc_81_bad.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-81_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE401_Memory_Leak__char_calloc_81.h"

namespace CWE401_Memory_Leak__char_calloc_81
{

void CWE401_Memory_Leak__char_calloc_81_bad::action(char * data) const
{
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

}
#endif /* OMITBAD */
