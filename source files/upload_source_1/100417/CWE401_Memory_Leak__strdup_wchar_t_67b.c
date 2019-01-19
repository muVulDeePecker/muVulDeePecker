/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__strdup_wchar_t_67b.c
Label Definition File: CWE401_Memory_Leak__strdup.label.xml
Template File: sources-sinks-67b.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource:  Allocate data using wcsdup()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE401_Memory_Leak__strdup_wchar_t_67_structType
{
    wchar_t * structFirst;
} CWE401_Memory_Leak__strdup_wchar_t_67_structType;

#ifndef OMITBAD

void CWE401_Memory_Leak__strdup_wchar_t_67b_badSink(CWE401_Memory_Leak__strdup_wchar_t_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    /* POTENTIAL FLAW: No deallocation of memory */
    /* no deallocation */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE401_Memory_Leak__strdup_wchar_t_67b_goodG2BSink(CWE401_Memory_Leak__strdup_wchar_t_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    /* POTENTIAL FLAW: No deallocation of memory */
    /* no deallocation */
    ; /* empty statement needed for some flow variants */
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE401_Memory_Leak__strdup_wchar_t_67b_goodB2GSink(CWE401_Memory_Leak__strdup_wchar_t_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    /* FIX: Deallocate memory initialized in the source */
    free(data);
}

#endif /* OMITGOOD */
