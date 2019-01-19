/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_environment_printf_84.h
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: environment Read input from an environment variable
 * GoodSource: Copy a fixed string into data
 * Sinks: printf
 *    GoodSink: printf with "%s" as the first argument and data as the second
 *    BadSink : printf with only data as an argument
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

namespace CWE134_Uncontrolled_Format_String__char_environment_printf_84
{

#ifndef OMITBAD

class CWE134_Uncontrolled_Format_String__char_environment_printf_84_bad
{
public:
    CWE134_Uncontrolled_Format_String__char_environment_printf_84_bad(char * dataCopy);
    ~CWE134_Uncontrolled_Format_String__char_environment_printf_84_bad();

private:
    char * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE134_Uncontrolled_Format_String__char_environment_printf_84_goodG2B
{
public:
    CWE134_Uncontrolled_Format_String__char_environment_printf_84_goodG2B(char * dataCopy);
    ~CWE134_Uncontrolled_Format_String__char_environment_printf_84_goodG2B();

private:
    char * data;
};

class CWE134_Uncontrolled_Format_String__char_environment_printf_84_goodB2G
{
public:
    CWE134_Uncontrolled_Format_String__char_environment_printf_84_goodB2G(char * dataCopy);
    ~CWE134_Uncontrolled_Format_String__char_environment_printf_84_goodB2G();

private:
    char * data;
};

#endif /* OMITGOOD */

}
