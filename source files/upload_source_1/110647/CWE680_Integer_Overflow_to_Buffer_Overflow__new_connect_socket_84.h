/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84.h
Label Definition File: CWE680_Integer_Overflow_to_Buffer_Overflow__new.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 680 Integer Overflow to Buffer Overflow
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Small number greater than zero that will not cause an integer overflow in the sink
 * Sinks:
 *    BadSink : Attempt to allocate array using length value from source
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

namespace CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84
{

#ifndef OMITBAD

class CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84_bad
{
public:
    CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84_bad(int dataCopy);
    ~CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84_bad();

private:
    int data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84_goodG2B
{
public:
    CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84_goodG2B(int dataCopy);
    ~CWE680_Integer_Overflow_to_Buffer_Overflow__new_connect_socket_84_goodG2B();

private:
    int data;
};

#endif /* OMITGOOD */

}
