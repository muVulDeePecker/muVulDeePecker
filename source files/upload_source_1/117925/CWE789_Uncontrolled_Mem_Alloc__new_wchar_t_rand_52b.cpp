/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__new_wchar_t_rand_52b.cpp
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__new.label.xml
Template File: sources-sinks-52b.tmpl.cpp
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: rand Set data to result of rand(), which may be zero
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with new [] and check the size of the memory to be allocated
 *    BadSink : Allocate memory with new [], but incorrectly check the size of the memory to be allocated
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

#define HELLO_STRING L"hello"

namespace CWE789_Uncontrolled_Mem_Alloc__new_wchar_t_rand_52
{

#ifndef OMITBAD

/* bad function declaration */
void badSink_c(size_t data);

void badSink_b(size_t data)
{
    badSink_c(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink_c(size_t data);

void goodG2BSink_b(size_t data)
{
    goodG2BSink_c(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink_c(size_t data);

void goodB2GSink_b(size_t data)
{
    goodB2GSink_c(data);
}

#endif /* OMITGOOD */

} /* close namespace */
