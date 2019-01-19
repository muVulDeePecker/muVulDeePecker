/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE690_NULL_Deref_From_Return__struct_realloc_66a.c
Label Definition File: CWE690_NULL_Deref_From_Return.free.label.xml
Template File: source-sinks-66a.tmpl.c
*/
/*
 * @description
 * CWE: 690 Unchecked Return Value To NULL Pointer
 * BadSource: realloc Allocate data using realloc()
 * Sinks:
 *    GoodSink: Check to see if the data allocation failed and if not, use data
 *    BadSink : Don't check for NULL and use data
 * Flow Variant: 66 Data flow: data passed in an array from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE690_NULL_Deref_From_Return__struct_realloc_66b_badSink(twoIntsStruct * dataArray[]);

void CWE690_NULL_Deref_From_Return__struct_realloc_66_bad()
{
    twoIntsStruct * data;
    twoIntsStruct * dataArray[5];
    data = NULL; /* Initialize data */
    /* POTENTIAL FLAW: Allocate memory without checking if the memory allocation function failed */
    data = (twoIntsStruct *)realloc(data, 1*sizeof(twoIntsStruct));
    /* put data in array */
    dataArray[2] = data;
    CWE690_NULL_Deref_From_Return__struct_realloc_66b_badSink(dataArray);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE690_NULL_Deref_From_Return__struct_realloc_66b_goodB2GSink(twoIntsStruct * dataArray[]);

static void goodB2G()
{
    twoIntsStruct * data;
    twoIntsStruct * dataArray[5];
    data = NULL; /* Initialize data */
    /* POTENTIAL FLAW: Allocate memory without checking if the memory allocation function failed */
    data = (twoIntsStruct *)realloc(data, 1*sizeof(twoIntsStruct));
    dataArray[2] = data;
    CWE690_NULL_Deref_From_Return__struct_realloc_66b_goodB2GSink(dataArray);
}

void CWE690_NULL_Deref_From_Return__struct_realloc_66_good()
{
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE690_NULL_Deref_From_Return__struct_realloc_66_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE690_NULL_Deref_From_Return__struct_realloc_66_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
