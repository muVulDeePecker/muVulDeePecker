/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE124_Buffer_Underwrite__new_char_memcpy_84.h
Label Definition File: CWE124_Buffer_Underwrite__new.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 124 Buffer Underwrite
 * BadSource:  Set data pointer to before the allocated memory buffer
 * GoodSource: Set data pointer to the allocated memory buffer
 * Sinks: memcpy
 *    BadSink : Copy string to data using memcpy
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE124_Buffer_Underwrite__new_char_memcpy_84
{

#ifndef OMITBAD

class CWE124_Buffer_Underwrite__new_char_memcpy_84_bad
{
public:
    CWE124_Buffer_Underwrite__new_char_memcpy_84_bad(char * dataCopy);
    ~CWE124_Buffer_Underwrite__new_char_memcpy_84_bad();

private:
    char * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE124_Buffer_Underwrite__new_char_memcpy_84_goodG2B
{
public:
    CWE124_Buffer_Underwrite__new_char_memcpy_84_goodG2B(char * dataCopy);
    ~CWE124_Buffer_Underwrite__new_char_memcpy_84_goodG2B();

private:
    char * data;
};

#endif /* OMITGOOD */

}
