/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83.h
Label Definition File: CWE789_Uncontrolled_Mem_Alloc__new.label.xml
Template File: sources-sinks-83.tmpl.h
*/
/*
 * @description
 * CWE: 789 Uncontrolled Memory Allocation
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Small number greater than zero
 * Sinks:
 *    GoodSink: Allocate memory with new [] and check the size of the memory to be allocated
 *    BadSink : Allocate memory with new [], but incorrectly check the size of the memory to be allocated
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

namespace CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83
{

#ifndef OMITBAD

class CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_bad
{
public:
    CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_bad(size_t dataCopy);
    ~CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_bad();

private:
    size_t data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_goodG2B
{
public:
    CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_goodG2B(size_t dataCopy);
    ~CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_goodG2B();

private:
    size_t data;
};

class CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_goodB2G
{
public:
    CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_goodB2G(size_t dataCopy);
    ~CWE789_Uncontrolled_Mem_Alloc__new_char_fscanf_83_goodB2G();

private:
    size_t data;
};

#endif /* OMITGOOD */

}
