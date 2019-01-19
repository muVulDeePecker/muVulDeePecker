/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_connect_socket_system_81.h
Label Definition File: CWE78_OS_Command_Injection.one_string.label.xml
Template File: sources-sink-81.tmpl.h
*/
/*
 * @description
 * CWE: 78 OS Command Injection
 * BadSource: connect_socket Read data using a connect socket (client side)
 * GoodSource: Fixed string
 * Sinks: system
 *    BadSink : Execute command in data using system()
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define FULL_COMMAND "%WINDIR%\\system32\\cmd.exe /c dir "
#else
#include <unistd.h>
#define FULL_COMMAND "/bin/sh ls -la "
#endif

namespace CWE78_OS_Command_Injection__char_connect_socket_system_81
{

class CWE78_OS_Command_Injection__char_connect_socket_system_81_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) const = 0;
};

#ifndef OMITBAD

class CWE78_OS_Command_Injection__char_connect_socket_system_81_bad : public CWE78_OS_Command_Injection__char_connect_socket_system_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITBAD */

#ifndef OMITGOOD

class CWE78_OS_Command_Injection__char_connect_socket_system_81_goodG2B : public CWE78_OS_Command_Injection__char_connect_socket_system_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITGOOD */

}
