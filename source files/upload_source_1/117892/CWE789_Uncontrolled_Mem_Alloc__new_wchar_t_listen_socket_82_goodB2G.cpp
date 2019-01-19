/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__new_wchar_t_listen_socket_82_goodB2G.cpp
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__new.label.xml
Template File: sources-sinks-82_goodB2G.tmpl.cpp
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: listen_socket Read data using a listen socket (server side)
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with new [] and check the size of the memory to be allocated
 *    BadSink : Allocate memory with new [], but incorrectly check the size of the memory to be allocated
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE789_Uncontrolled_Mem_Alloc__new_wchar_t_listen_socket_82.h"

#define HELLO_STRING L"hello"

namespace CWE789_Uncontrolled_Mem_Alloc__new_wchar_t_listen_socket_82
{

void CWE789_Uncontrolled_Mem_Alloc__new_wchar_t_listen_socket_82_goodB2G::action(size_t data)
{
    {
        wchar_t * myString;
        /* FIX: Include a MAXIMUM limitation for memory allocation and a check to ensure data is large enough
         * for the wcscpy() function to not cause a buffer overflow */
        /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
        if (data > wcslen(HELLO_STRING) && data < 100)
        {
            myString = new wchar_t[data];
            /* Copy a small string into myString */
            wcscpy(myString, HELLO_STRING);
            printWLine(myString);
            delete [] myString;
        }
        else
        {
            printLine("Input is less than the length of the source string or too large");
        }
    }
}

}
#endif /* OMITGOOD */
