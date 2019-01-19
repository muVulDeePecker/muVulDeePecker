/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__wchar_t_console_system_84_goodG2B.cpp
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-84_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: console Read input from the console
 * GoodSource: Fixed string
 * Sinks: system
 *    BadSink : Execute command in data using system()
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE78_OS_Command_Injection__wchar_t_console_system_84.h"

#ifdef _WIN32
#define SYSTEM _wsystem
#else /* NOT _WIN32 */
#define SYSTEM system
#endif

namespace CWE78_OS_Command_Injection__wchar_t_console_system_84
{
CWE78_OS_Command_Injection__wchar_t_console_system_84_goodG2B::CWE78_OS_Command_Injection__wchar_t_console_system_84_goodG2B(wchar_t * dataCopy)
{
    data = dataCopy;
    /* FIX: Append a fixed string to data (not user / external input) */
    wcscat(data, L"*.*");
}

CWE78_OS_Command_Injection__wchar_t_console_system_84_goodG2B::~CWE78_OS_Command_Injection__wchar_t_console_system_84_goodG2B()
{
    /* POTENTIAL FLAW: Execute command in data possibly leading to command injection */
    if (SYSTEM(data) <= 0)
    {
        printLine("command execution failed!");
        exit(1);
    }
}
}
#endif /* OMITGOOD */
