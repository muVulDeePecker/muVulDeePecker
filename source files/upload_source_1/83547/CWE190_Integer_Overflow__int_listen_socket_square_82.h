/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE190_Integer_Overflow__int_listen_socket_square_82.h
Label Definition File: CWE190_Integer_Overflow__int.label.xml
Template File: sources-sinks-82.tmpl.h
*/
/*
 * @description
 * CWE: 190 Integer Overflow
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Set data to a small, non-zero number (two)
 * Sinks: square
 *    GoodSink: Ensure there will not be an overflow before squaring data
 *    BadSink : Square data, which can lead to overflow
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

namespace CWE190_Integer_Overflow__int_listen_socket_square_82
{

class CWE190_Integer_Overflow__int_listen_socket_square_82_base
{
public:
    /* pure virtual function */
    virtual void action(int data) = 0;
};

#ifndef OMITBAD

class CWE190_Integer_Overflow__int_listen_socket_square_82_bad : public CWE190_Integer_Overflow__int_listen_socket_square_82_base
{
public:
    void action(int data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE190_Integer_Overflow__int_listen_socket_square_82_goodG2B : public CWE190_Integer_Overflow__int_listen_socket_square_82_base
{
public:
    void action(int data);
};

class CWE190_Integer_Overflow__int_listen_socket_square_82_goodB2G : public CWE190_Integer_Overflow__int_listen_socket_square_82_base
{
public:
    void action(int data);
};

#endif /* OMITGOOD */

}
