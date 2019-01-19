/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE680_Integer_Overflow_to_Buffer_Overflow__new_listen_socket_83_goodG2B.cpp
Label Definition File: CWE680_Integer_Overflow_to_Buffer_Overflow__new.label.xml
Template File: sources-sink-83_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 680 Integer Overflow to Buffer Overflow
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Small number greater than zero that will not cause an integer overflow in the sink
 * Sinks:
 *    BadSink : Attempt to allocate array using length value from source
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE680_Integer_Overflow_to_Buffer_Overflow__new_listen_socket_83.h"

namespace CWE680_Integer_Overflow_to_Buffer_Overflow__new_listen_socket_83
{
CWE680_Integer_Overflow_to_Buffer_Overflow__new_listen_socket_83_goodG2B::CWE680_Integer_Overflow_to_Buffer_Overflow__new_listen_socket_83_goodG2B(int dataCopy)
{
    data = dataCopy;
    /* FIX: Set data to a relatively small number greater than zero */
    data = 20;
}

CWE680_Integer_Overflow_to_Buffer_Overflow__new_listen_socket_83_goodG2B::~CWE680_Integer_Overflow_to_Buffer_Overflow__new_listen_socket_83_goodG2B()
{
    {
        size_t dataBytes,i;
        int *intPointer;
        /* POTENTIAL FLAW: dataBytes may overflow to a small value */
        dataBytes = data * sizeof(int); /* sizeof array in bytes */
        intPointer = (int*)new char[dataBytes];
        for (i = 0; i < (size_t)data; i++)
        {
            intPointer[i] = 0; /* may write beyond limit of intPointer if integer overflow occured above */
        }
        printIntLine(intPointer[0]);
        delete [] intPointer;
    }
}
}
#endif /* OMITGOOD */
