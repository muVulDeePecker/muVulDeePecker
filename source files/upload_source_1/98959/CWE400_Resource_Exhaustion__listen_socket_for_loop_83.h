/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE400_Resource_Exhaustion__listen_socket_for_loop_83.h
Label Definition File: CWE400_Resource_Exhaustion.label.xml
Template File: sources-sinks-83.tmpl.h
*/
/*
 * @description
 * CWE: 400 Resource Exhaustion
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Assign count to be a relatively small number
 * Sinks: for_loop
 *    GoodSink: Validate count before using it as the loop variant in a for loop
 *    BadSink : Use count as the loop variant in a for loop
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"

namespace CWE400_Resource_Exhaustion__listen_socket_for_loop_83
{

#ifndef OMITBAD

class CWE400_Resource_Exhaustion__listen_socket_for_loop_83_bad
{
public:
    CWE400_Resource_Exhaustion__listen_socket_for_loop_83_bad(int countCopy);
    ~CWE400_Resource_Exhaustion__listen_socket_for_loop_83_bad();

private:
    int count;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE400_Resource_Exhaustion__listen_socket_for_loop_83_goodG2B
{
public:
    CWE400_Resource_Exhaustion__listen_socket_for_loop_83_goodG2B(int countCopy);
    ~CWE400_Resource_Exhaustion__listen_socket_for_loop_83_goodG2B();

private:
    int count;
};

class CWE400_Resource_Exhaustion__listen_socket_for_loop_83_goodB2G
{
public:
    CWE400_Resource_Exhaustion__listen_socket_for_loop_83_goodB2G(int countCopy);
    ~CWE400_Resource_Exhaustion__listen_socket_for_loop_83_goodB2G();

private:
    int count;
};

#endif /* OMITGOOD */

}
