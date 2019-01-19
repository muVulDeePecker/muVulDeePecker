/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_81_goodB2G.cpp
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__new.label.xml
Template File: sources-sinks-81_goodB2G.tmpl.cpp
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: fgets Read data from the console using fgets()
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with new [] and check the size of the memory to be allocated
 *    BadSink : Allocate memory with new [], but incorrectly check the size of the memory to be allocated
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_81.h"

#define HELLO_STRING "hello"

namespace CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_81
{

void CWE789_Uncontrolled_Mem_Alloc__new_char_fgets_81_goodB2G::action(size_t data) const
{
    {
        char * myString;
        /* FIX: Include a MAXIMUM limitation for memory allocation and a check to ensure data is large enough
         * for the strcpy() function to not cause a buffer overflow */
        /* INCIDENTAL FLAW: The source could cause a type overrun in data or in the memory allocation */
        if (data > strlen(HELLO_STRING) && data < 100)
        {
            myString = new char[data];
            /* Copy a small string into myString */
            strcpy(myString, HELLO_STRING);
            printLine(myString);
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
