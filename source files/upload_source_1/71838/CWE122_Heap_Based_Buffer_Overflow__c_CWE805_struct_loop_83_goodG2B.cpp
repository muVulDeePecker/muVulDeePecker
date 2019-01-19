/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_83_goodG2B.cpp
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__c_CWE805.label.xml
Template File: sources-sink-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource:  Allocate using malloc() and set data pointer to a small buffer
 * GoodSource: Allocate using malloc() and set data pointer to a large buffer
 * Sinks: loop
 *    BadSink : Copy twoIntsStruct array to data using a loop
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_83.h"

namespace CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_83
{
CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_83_goodG2B::CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_83_goodG2B(twoIntsStruct * dataCopy)
{
    data = dataCopy;
    /* FIX: Allocate and point data to a large buffer that is at least as large as the large buffer used in the sink */
    data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
}

CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_83_goodG2B::~CWE122_Heap_Based_Buffer_Overflow__c_CWE805_struct_loop_83_goodG2B()
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intTwo = 0;
            }
        }
        {
            size_t i;
            /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printStructLine(&data[0]);
            free(data);
        }
    }
}
}
#endif /* OMITGOOD */
