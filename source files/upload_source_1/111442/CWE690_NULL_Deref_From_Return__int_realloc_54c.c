/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE690_NULL_Deref_From_Return__int_realloc_54c.c
Label Definition File: CWE690_NULL_Deref_From_Return.free.label.xml
Template File: source-sinks-54c.tmpl.c
*/
/*
 * @description
 * CWE: 690 Unchecked Return Value To NULL Pointer
 * BadSource: realloc Allocate data using realloc()
 * Sinks:
 *    GoodSink: Check to see if the data allocation failed and if not, use data
 *    BadSink : Don't check for NULL and use data
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE690_NULL_Deref_From_Return__int_realloc_54d_badSink(int * data);

void CWE690_NULL_Deref_From_Return__int_realloc_54c_badSink(int * data)
{
    CWE690_NULL_Deref_From_Return__int_realloc_54d_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE690_NULL_Deref_From_Return__int_realloc_54d_goodB2GSink(int * data);

void CWE690_NULL_Deref_From_Return__int_realloc_54c_goodB2GSink(int * data)
{
    CWE690_NULL_Deref_From_Return__int_realloc_54d_goodB2GSink(data);
}

#endif /* OMITGOOD */
