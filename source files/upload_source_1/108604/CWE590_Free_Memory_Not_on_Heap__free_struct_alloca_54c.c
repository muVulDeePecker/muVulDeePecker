/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE590_Free_Memory_Not_on_Heap__free_struct_alloca_54c.c
Label Definition File: CWE590_Free_Memory_Not_on_Heap__free.label.xml
Template File: sources-sink-54c.tmpl.c
*/
/*
 * @description
 * CWE: 590 Free Memory Not on Heap
 * BadSource: alloca Data buffer is allocated on the stack with alloca()
 * GoodSource: Allocate memory on the heap
 * Sink:
 *    BadSink : Print then free data
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

/* bad function declaration */
void CWE590_Free_Memory_Not_on_Heap__free_struct_alloca_54d_badSink(twoIntsStruct * data);

void CWE590_Free_Memory_Not_on_Heap__free_struct_alloca_54c_badSink(twoIntsStruct * data)
{
    CWE590_Free_Memory_Not_on_Heap__free_struct_alloca_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declaration */
void CWE590_Free_Memory_Not_on_Heap__free_struct_alloca_54d_goodG2BSink(twoIntsStruct * data);

/* goodG2B uses the GoodSource with the BadSink */
void CWE590_Free_Memory_Not_on_Heap__free_struct_alloca_54c_goodG2BSink(twoIntsStruct * data)
{
    CWE590_Free_Memory_Not_on_Heap__free_struct_alloca_54d_goodG2BSink(data);
}

#endif /* OMITGOOD */
