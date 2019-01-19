/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE127_Buffer_Underread__malloc_wchar_t_ncpy_82.h
Label Definition File: CWE127_Buffer_Underread__malloc.label.xml
Template File: sources-sink-82.tmpl.h
*/
/*
 * @description
 * CWE: 127 Buffer Under-read
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 *    BadSink : Copy data to string using wcsncpy
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE127_Buffer_Underread__malloc_wchar_t_ncpy_82
{

class CWE127_Buffer_Underread__malloc_wchar_t_ncpy_82_base
{
public:
    /* pure virtual function */
    virtual void action(wchar_t * data) = 0;
};

#ifndef OMITBAD

class CWE127_Buffer_Underread__malloc_wchar_t_ncpy_82_bad : public CWE127_Buffer_Underread__malloc_wchar_t_ncpy_82_base
{
public:
    void action(wchar_t * data);
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE127_Buffer_Underread__malloc_wchar_t_ncpy_82_goodG2B : public CWE127_Buffer_Underread__malloc_wchar_t_ncpy_82_base
{
public:
    void action(wchar_t * data);
};

#endif /* OMITGOOD */

}
