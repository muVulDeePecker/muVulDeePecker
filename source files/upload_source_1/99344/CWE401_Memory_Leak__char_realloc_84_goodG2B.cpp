/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__char_realloc_84_goodG2B.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: realloc Allocate data using realloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE401_Memory_Leak__char_realloc_84.h"

namespace CWE401_Memory_Leak__char_realloc_84
{
CWE401_Memory_Leak__char_realloc_84_goodG2B::CWE401_Memory_Leak__char_realloc_84_goodG2B(char * dataCopy)
{
    data = dataCopy;
    /* FIX: Use memory allocated on the stack with ALLOCA */
    data = (char *)ALLOCA(100*sizeof(char));
    /* Initialize and make use of data */
    strcpy(data, "A String");
    printLine(data);
}

CWE401_Memory_Leak__char_realloc_84_goodG2B::~CWE401_Memory_Leak__char_realloc_84_goodG2B()
{
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}
}
#endif /* OMITGOOD */
