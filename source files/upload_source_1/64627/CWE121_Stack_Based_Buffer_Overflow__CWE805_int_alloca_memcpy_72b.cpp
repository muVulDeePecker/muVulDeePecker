/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_72b.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-72b.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sinks: memcpy
 *    BadSink : Copy int array to data using memcpy
 * Flow Variant: 72 Data flow: data passed in a vector from one function to another in different source files
 *
 * */

#include "std_testcase.h"
#include <vector>

using namespace std;

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_72
{

#ifndef OMITBAD

void badSink(vector<int *> dataVector)
{
    /* copy data out of dataVector */
    int * data = dataVector[2];
    {
        int source[100] = {0}; /* fill with 0's */
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memcpy(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(vector<int *> dataVector)
{
    int * data = dataVector[2];
    {
        int source[100] = {0}; /* fill with 0's */
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memcpy(data, source, 100*sizeof(int));
        printIntLine(data[0]);
    }
}

#endif /* OMITGOOD */

} /* close namespace */
