/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__int_malloc_74b.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-74b.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: malloc Allocate data using malloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 74 Data flow: data passed in a map from one function to another in different source files
 *
 * */

#include "std_testcase.h"
#include <map>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__int_malloc_74
{

#ifndef OMITBAD

void badSink(map<int, int *> dataMap)
{
    /* copy data out of dataMap */
    int * data = dataMap[2];
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(map<int, int *> dataMap)
{
    int * data = dataMap[2];
    /* POTENTIAL FLAW: No deallocation */
    ; /* empty statement needed for some flow variants */
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink(map<int, int *> dataMap)
{
    int * data = dataMap[2];
    /* FIX: Deallocate memory */
    free(data);
}

#endif /* OMITGOOD */

} /* close namespace */
