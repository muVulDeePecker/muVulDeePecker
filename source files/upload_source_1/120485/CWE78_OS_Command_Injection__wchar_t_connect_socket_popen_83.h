/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83.h
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-83.tmpl.h
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Fixed string
 * Sinks: popen
 *    BadSink : Execute command in data using popen()
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define FULL_COMMAND L"%WINDIR%\\system32\\cmd.exe /c dir "
#else
#include <unistd.h>
#define FULL_COMMAND L"/bin/sh ls -la "
#endif

namespace CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83
{

#ifndef OMITBAD

class CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83_bad
{
public:
    CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83_bad(wchar_t * dataCopy);
    ~CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83_bad();

private:
    wchar_t * data;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83_goodG2B
{
public:
    CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83_goodG2B(wchar_t * dataCopy);
    ~CWE78_OS_Command_Injection__wchar_t_connect_socket_popen_83_goodG2B();

private:
    wchar_t * data;
};

#endif /* OMITGOOD */

}
