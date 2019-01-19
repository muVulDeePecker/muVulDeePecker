/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82.h
Label Definition File: CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129.label.xml
Template File: sources-sinks-82.tmpl.h
*/
/*
 * @description
 * CWE: 122 Heap Based Buffer Overflow
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Larger than zero but less than 10
 * Sinks:
 *    GoodSink: Ensure the array index is valid
 *    BadSink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

namespace CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82
{

class CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82_base
{
public:
    /* pure virtual function */
    virtual void action(int data) = 0;
};

#ifndef OMITBAD

class CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82_bad : public CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82_base
{
public:
    void action(int data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82_goodG2B : public CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82_base
{
public:
    void action(int data);
};

class CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82_goodB2G : public CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_listen_socket_82_base
{
public:
    void action(int data);
};

#endif /* OMITGOOD */

}
