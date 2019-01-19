/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE126_Buffer_Overread__malloc_wchar_t_memmove_84.h
Label Definition File: CWE126_Buffer_Overread__malloc.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 126 Buffer Over-read
 * BadSource:  Use a small buffer
 * GoodSource: Use a large buffer
 * Sinks: memmove
 *    BadSink : Copy data to string using memmove
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE126_Buffer_Overread__malloc_wchar_t_memmove_84
{

#ifndef OMITBAD

class CWE126_Buffer_Overread__malloc_wchar_t_memmove_84_bad
{
public:
    CWE126_Buffer_Overread__malloc_wchar_t_memmove_84_bad(wchar_t * dataCopy);
    ~CWE126_Buffer_Overread__malloc_wchar_t_memmove_84_bad();

private:
    wchar_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE126_Buffer_Overread__malloc_wchar_t_memmove_84_goodG2B
{
public:
    CWE126_Buffer_Overread__malloc_wchar_t_memmove_84_goodG2B(wchar_t * dataCopy);
    ~CWE126_Buffer_Overread__malloc_wchar_t_memmove_84_goodG2B();

private:
    wchar_t * data;
};

#endif /* OMITGOOD */

}
