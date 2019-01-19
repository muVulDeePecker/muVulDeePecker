/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__char_alloca_memmove_82.h
Label Definition File: CWE127_Buffer_Underread.stack.label.xml
Template File: sources-sink-82.tmpl.h
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 *    BadSink : Copy data to string using memmove
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE127_Buffer_Underread__char_alloca_memmove_82
{

class CWE127_Buffer_Underread__char_alloca_memmove_82_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) = 0;
};

#ifndef OMITBAD

class CWE127_Buffer_Underread__char_alloca_memmove_82_bad : public CWE127_Buffer_Underread__char_alloca_memmove_82_base
{
public:
    void action(char * data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE127_Buffer_Underread__char_alloca_memmove_82_goodG2B : public CWE127_Buffer_Underread__char_alloca_memmove_82_base
{
public:
    void action(char * data);
};

#endif /* OMITGOOD */

}
