/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_81_bad.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-81_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sinks: memcpy
 *    BadSink : Copy twoIntsStruct array to data using memcpy
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memcpy_81_bad::action(twoIntsStruct * data) const
{
    {
        twoIntsStruct source[100];
        {
            size_t i;
            /* Initialize array */
            for (i = 0; i < 100; i++)
            {
                source[i].intOne = 0;
                source[i].intOne = 0;
            }
        }
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memcpy(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

}
#endif /* OMITBAD */
