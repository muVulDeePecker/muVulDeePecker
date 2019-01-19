/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82.h
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__new.label.xml
Template File: sources-sinks-82.tmpl.h
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with new [] and check the size of the memory to be allocated
 *    BadSink : Allocate memory with new [], but incorrectly check the size of the memory to be allocated
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

namespace CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82
{

class CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82_base
{
public:
    /* pure virtual function */
    virtual void action(size_t data) = 0;
};

#ifndef OMITBAD

class CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82_bad : public CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82_base
{
public:
    void action(size_t data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82_goodG2B : public CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82_base
{
public:
    void action(size_t data);
};

class CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82_goodB2G : public CWE789_Uncontrolled_Mem_Alloc__new_char_connect_socket_82_base
{
public:
    void action(size_t data);
};

#endif /* OMITGOOD */

}
