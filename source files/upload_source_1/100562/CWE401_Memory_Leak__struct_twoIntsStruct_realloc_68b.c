/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68b.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-68b.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: realloc Allocate data using realloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

extern struct _twoIntsStruct * CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68_badData;
extern struct _twoIntsStruct * CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68_goodG2BData;
extern struct _twoIntsStruct * CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68_goodB2GData;

#ifndef OMITBAD

void CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68b_badSink()
{
    struct _twoIntsStruct * data = CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68_badData;
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68b_goodG2BSink()
{
    struct _twoIntsStruct * data = CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68_goodG2BData;
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68b_goodB2GSink()
{
    struct _twoIntsStruct * data = CWE401_Memory_Leak__struct_twoIntsStruct_realloc_68_goodB2GData;
    /* FIX: Deallocate memory */
    free(data);
}

#endif /* OMITGOOD */
