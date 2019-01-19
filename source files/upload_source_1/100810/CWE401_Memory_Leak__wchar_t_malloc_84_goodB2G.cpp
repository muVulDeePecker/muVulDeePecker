/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__wchar_t_malloc_84_goodB2G.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-84_goodB2G.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: malloc Allocate data using malloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE401_Memory_Leak__wchar_t_malloc_84.h"

namespace CWE401_Memory_Leak__wchar_t_malloc_84
{
CWE401_Memory_Leak__wchar_t_malloc_84_goodB2G::CWE401_Memory_Leak__wchar_t_malloc_84_goodB2G(wchar_t * dataCopy)
{
    data = dataCopy;
    /* POTENTIAL FLAW: Allocate memory on the heap */
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    /* Initialize and make use of data */
    wcscpy(data, L"A String");
    printWLine(data);
}

CWE401_Memory_Leak__wchar_t_malloc_84_goodB2G::~CWE401_Memory_Leak__wchar_t_malloc_84_goodB2G()
{
    /* FIX: Deallocate memory */
    free(data);
}
}
#endif /* OMITGOOD */
