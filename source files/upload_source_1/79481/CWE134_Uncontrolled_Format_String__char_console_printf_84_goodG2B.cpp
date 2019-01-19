/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_console_printf_84_goodG2B.cpp
Label Definition File: CWE134_Uncontrolled_Format_String.label.xml
Template File: sources-sinks-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 134 Uncontrolled Format String
 * BadSource: console Read input from the console
 * GoodSource: Copy a fixed string into data
 * Sinks: printf
 *    GoodSink: printf with "%s" as the first argument and data as the second
 *    BadSink : printf with only data as an argument
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE134_Uncontrolled_Format_String__char_console_printf_84.h"

namespace CWE134_Uncontrolled_Format_String__char_console_printf_84
{
CWE134_Uncontrolled_Format_String__char_console_printf_84_goodG2B::CWE134_Uncontrolled_Format_String__char_console_printf_84_goodG2B(char * dataCopy)
{
    data = dataCopy;
    /* FIX: Use a fixed string that does not contain a format specifier */
    strcpy(data, "fixedstringtest");
}

CWE134_Uncontrolled_Format_String__char_console_printf_84_goodG2B::~CWE134_Uncontrolled_Format_String__char_console_printf_84_goodG2B()
{
    /* POTENTIAL FLAW: Do not specify the format allowing a possible format string vulnerability */
    printf(data);
}
}
#endif /* OMITGOOD */
