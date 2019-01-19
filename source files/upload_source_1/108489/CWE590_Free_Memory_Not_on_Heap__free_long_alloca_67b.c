/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE590_Free_Memory_Not_on_Heap__free_long_alloca_67b.c
Label Definition File: CWE590_Free_Memory_Not_on_Heap__free.label.xml
Template File: sources-sink-67b.tmpl.c
*/
/*
 * @description
 * CWE: 590 Free Memory Not on Heap
 * BadSource: alloca Data buffer is allocated on the stack with alloca()
 * GoodSource: Allocate memory on the heap
 * Sinks:
 *    BadSink : Print then free data
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

typedef struct _CWE590_Free_Memory_Not_on_Heap__free_long_alloca_67_structType
{
    long * structFirst;
} CWE590_Free_Memory_Not_on_Heap__free_long_alloca_67_structType;

#ifndef OMITBAD

void CWE590_Free_Memory_Not_on_Heap__free_long_alloca_67b_badSink(CWE590_Free_Memory_Not_on_Heap__free_long_alloca_67_structType myStruct)
{
    long * data = myStruct.structFirst;
    printLongLine(data[0]);
    /* POTENTIAL FLAW: Possibly deallocating memory allocated on the stack */
    free(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE590_Free_Memory_Not_on_Heap__free_long_alloca_67b_goodG2BSink(CWE590_Free_Memory_Not_on_Heap__free_long_alloca_67_structType myStruct)
{
    long * data = myStruct.structFirst;
    printLongLine(data[0]);
    /* POTENTIAL FLAW: Possibly deallocating memory allocated on the stack */
    free(data);
}

#endif /* OMITGOOD */
