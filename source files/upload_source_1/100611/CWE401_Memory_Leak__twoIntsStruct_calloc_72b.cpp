/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__twoIntsStruct_calloc_72b.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-72b.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 72 Data flow: data passed in a vector from one function to another in different source files
 *
 * */

#include "std_testcase.h"
#include <vector>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__twoIntsStruct_calloc_72
{

#ifndef OMITBAD

void badSink(vector<twoIntsStruct *> dataVector)
{
    /* copy data out of dataVector */
    twoIntsStruct * data = dataVector[2];
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(vector<twoIntsStruct *> dataVector)
{
    twoIntsStruct * data = dataVector[2];
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink(vector<twoIntsStruct *> dataVector)
{
    twoIntsStruct * data = dataVector[2];
    /* FIX: Deallocate memory */
    free(data);
}

#endif /* OMITGOOD */

} /* close namespace */
