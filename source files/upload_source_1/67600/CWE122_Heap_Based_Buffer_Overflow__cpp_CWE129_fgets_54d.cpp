/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_fgets_54d.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129.label.xml
Template File: sources-sinks-54d.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Larger than zero but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_fgets_54
{

#ifndef OMITBAD

/* bad function declaration */
void badSink_e(int data);

void badSink_d(int data)
{
    badSink_e(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink_e(int data);

void goodG2BSink_d(int data)
{
    goodG2BSink_e(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink_e(int data);

void goodB2GSink_d(int data)
{
    goodB2GSink_e(data);
}

#endif /* OMITGOOD */

} /* close namespace */
